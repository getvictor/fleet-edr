package pipeline

import (
	"context"
	"errors"
	"log/slog"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
	"go.opentelemetry.io/otel/trace"

	"github.com/fleetdm/edr/server/detection/api"
	rulesapi "github.com/fleetdm/edr/server/rules/api"
	visibilityapi "github.com/fleetdm/edr/server/visibility/api"
)

// installSpanRecorder points the global tracer provider at an in-memory recorder for the rest of the test. The callers are top-level
// serial tests: Go holds every t.Parallel test until the serial ones finish, so nothing else reads the global meanwhile.
func installSpanRecorder(t *testing.T) *tracetest.SpanRecorder {
	t.Helper()
	recorder := tracetest.NewSpanRecorder()
	provider := sdktrace.NewTracerProvider(sdktrace.WithSpanProcessor(recorder))
	previous := otel.GetTracerProvider()
	otel.SetTracerProvider(provider)
	t.Cleanup(func() {
		otel.SetTracerProvider(previous)
		_ = provider.Shutdown(context.Background())
	})
	return recorder
}

func endedSpansNamed(recorder *tracetest.SpanRecorder, name string) []sdktrace.ReadOnlySpan {
	var out []sdktrace.ReadOnlySpan
	for _, s := range recorder.Ended() {
		if s.Name() == name {
			out = append(out, s)
		}
	}
	return out
}

// spanContextEvaluator records the span context detection was called under, which is what makes the engine's per-rule spans and the
// batch's queries children of the batch span.
type spanContextEvaluator struct{ seen *trace.SpanContext }

func (e spanContextEvaluator) Evaluate(ctx context.Context, _ []visibilityapi.Event) (rulesapi.MonitorTally, error) {
	*e.seen = trace.SpanContextFromContext(ctx)
	return nil, nil
}

// spec:observability-instrumentation/background-work-is-traced-under-a-sampled-root-span/a-detection-batch-span-names-its-host
func TestProcessor_BatchRunsUnderARootSpanNamingItsHost(t *testing.T) { //nolint:paralleltest // installs the global tracer provider
	recorder := installSpanRecorder(t)
	var seen trace.SpanContext
	log := &scriptedEventLog{batch: oneEventBatch()}
	p := newTestProcessor(t, log, stubBuilder{}, spanContextEvaluator{seen: &seen}, singleCycleOpts(&capturingLogHandler{}))

	p.ProcessOnce(context.Background())

	batches := endedSpansNamed(recorder, api.BatchSpanName)
	require.Len(t, batches, 1, "one claimed batch is one batch span")
	batch := batches[0]
	assert.False(t, batch.Parent().IsValid(), "the batch span is a root, so the sampler classifies it by its own name")
	assert.Contains(t, batch.Attributes(), attribute.String("host_id", "host-a"))
	assert.Contains(t, batch.Attributes(), attribute.Int("edr.batch.events", 1))
	assert.Equal(t, batch.SpanContext(), seen, "detection must run under the batch span so its spans follow the batch's sampling")
	assert.Equal(t, []string{"evt-1"}, log.acked)
}

// spec:observability-instrumentation/background-work-is-traced-under-a-sampled-root-span/a-periodic-sweep-pass-is-one-trace
func TestRunPass_IsOneRootSpanPerPass(t *testing.T) { //nolint:paralleltest // installs the global tracer provider
	recorder := installSpanRecorder(t)
	const spanName = "detection.periodic.retention"

	t.Run("a pass parents the work it does", func(t *testing.T) {
		recorder.Reset()
		err := runPass(context.Background(), "retention", func(ctx context.Context) (int64, error) {
			_, child := otel.Tracer("test").Start(ctx, "sql.stmt.exec")
			child.End()
			return 3, nil
		})
		require.NoError(t, err)

		passes := endedSpansNamed(recorder, spanName)
		require.Len(t, passes, 1)
		assert.False(t, passes[0].Parent().IsValid(), "a pass is a root span")
		assert.Equal(t, codes.Unset, passes[0].Status().Code)
		children := endedSpansNamed(recorder, "sql.stmt.exec")
		require.Len(t, children, 1)
		assert.Equal(t, passes[0].SpanContext().SpanID(), children[0].Parent().SpanID(), "the pass's queries are its children")
	})

	t.Run("a failed pass records the error on its span", func(t *testing.T) {
		recorder.Reset()
		passErr := errors.New("prune alerts: lock wait timeout")
		err := runPass(context.Background(), "retention", func(context.Context) (int64, error) { return 0, passErr })
		require.ErrorIs(t, err, passErr, "the driver still sees the error, so it is still logged")

		passes := endedSpansNamed(recorder, spanName)
		require.Len(t, passes, 1)
		assert.Equal(t, codes.Error, passes[0].Status().Code)
		assert.Equal(t, passErr.Error(), passes[0].Status().Description)
	})

	t.Run("the periodic driver runs each pass through it", func(t *testing.T) {
		recorder.Reset()
		ctx, cancel := context.WithCancel(context.Background())
		runPeriodic(ctx, time.Hour, slog.Default(), "retention", func(context.Context) (int64, error) {
			cancel()
			return 0, nil
		})
		assert.Len(t, endedSpansNamed(recorder, spanName), 1, "the immediate first pass is traced")
	})
}
