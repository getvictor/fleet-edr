//go:build windows

package wintel

import (
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/google/uuid"
	"golang.org/x/sys/windows"

	"github.com/fleetdm/edr/agent/receiver"
	"github.com/fleetdm/edr/agent/wintel/etw"
)

// kernelProcessGUID is Microsoft-Windows-Kernel-Process {22FB2CD6-0E7B-422B-A0C7-2FAD1FD0E716}. keyword 0x10 = WINEVENT_KEYWORD_PROCESS
// (process start/stop). This is the driverless, MVI-free process telemetry source (ADR-0018, Phase 1).
var kernelProcessGUID = windows.GUID{Data1: 0x22FB2CD6, Data2: 0x0E7B, Data3: 0x422B, Data4: [8]byte{0xA0, 0xC7, 0x2F, 0xAD, 0x1F, 0xD0, 0xE7, 0x16}}

const (
	kernelProcessKeywordProcess = 0x10
	sessionName                 = "fleet-edr-kernel-process"
	eventProcessStart           = 1
	eventProcessStop            = 2
)

// SensorLabel is the log/heartbeat identity for the Windows ETW sensor. The agent uses it as the receiver.Loop ServiceName AND the
// sensor stamps it as the drop-warning "service", so every Windows sensor log line (connect/heartbeat/error and dropped-event) shares
// one value for correlation. It is deliberately distinct from sessionName, which is the OS ETW session object name, not a log label.
const SensorLabel = "windows-etw"

// ErrUnsupported is returned by SendApplicationControl: application-control enforcement is a privileged-tier (ELAM/PPL) capability the
// driverless sensor does not provide yet (ADR-0018, Phase 3).
var ErrUnsupported = errors.New("wintel: application control not supported on the driverless Windows sensor")

// Sensor consumes the Kernel-Process ETW provider and emits exec/exit event envelopes. It implements receiver.Connector so it plugs
// into the same reconnect/backoff/heartbeat loop the macOS XPC receiver uses. The loop builds a fresh Sensor per connect via the
// factory, so one Sensor owns one session+consumer lifecycle.
type Sensor struct {
	hostID string
	logger *slog.Logger
	events chan receiver.Event
	errs   chan int
	drops  *receiver.DropReporter // coalesces "channel full" drop warnings so a burst does not flood the log

	mu        sync.Mutex
	session   *etw.Session
	consumer  *etw.Consumer
	deviceMap map[string]string
	running   bool
	wg        sync.WaitGroup // tracks the ProcessTrace goroutine so Disconnect can wait for it before closing the trace
}

// New builds a Windows ETW sensor. eventBuf sizes the Events() channel; hostID is stamped on every envelope (the agent authors the
// envelope on Windows, unlike macOS where the extension does).
func New(hostID string, eventBuf int, logger *slog.Logger) *Sensor {
	if logger == nil {
		logger = slog.Default()
	}
	return &Sensor{
		hostID: hostID,
		logger: logger,
		events: make(chan receiver.Event, eventBuf),
		errs:   make(chan int, 8),
		drops:  receiver.NewDropReporter(),
	}
}

// Connect starts the ETW session, enables Kernel-Process, opens the consumer, and runs ProcessTrace on a goroutine. It returns once the
// session is live; event delivery happens asynchronously via Events().
func (s *Sensor) Connect() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.deviceMap = buildDeviceMap()

	sess, err := etw.StartSession(sessionName)
	if err != nil {
		return err
	}
	if err := sess.EnableProvider(kernelProcessGUID, kernelProcessKeywordProcess); err != nil {
		_ = sess.Stop()
		return err
	}
	consumer, err := etw.OpenConsumer(sess.Name(), s.handle)
	if err != nil {
		_ = sess.Stop()
		return err
	}
	s.session = sess
	s.consumer = consumer
	s.running = true

	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		// Process blocks until the session is stopped (Disconnect) or errors. A non-nil return while we still think we are running is a
		// dropped session: signal the loop so it reconnects.
		perr := consumer.Process()
		s.mu.Lock()
		wasRunning := s.running
		s.running = false
		s.mu.Unlock()
		if wasRunning {
			if perr != nil {
				s.logger.Warn("etw ProcessTrace ended", "err", perr)
			}
			select {
			case s.errs <- receiver.ErrorTerminated:
			default:
			}
		}
	}()
	return nil
}

// handle maps a Kernel-Process event to an envelope and enqueues it. Runs on the ProcessTrace thread; it must not block, so a full
// Events() buffer drops the event rather than stalling the trace (which would lose events kernel-side anyway). The drop is delivered
// through receiver.TryDeliverEvent so it shares the macOS receiver's non-blocking send + coalesced "channel full" warning instead of
// logging one line per dropped event.
func (s *Sensor) handle(r etw.Record) {
	var data []byte
	var err error
	switch r.EventID() {
	case eventProcessStart:
		data, err = s.execFromRecord(r)
	case eventProcessStop:
		data, err = s.exitFromRecord(r)
	default:
		return
	}
	if err != nil {
		s.logger.Warn("etw map event", "event_id", r.EventID(), "err", err)
		return
	}
	receiver.TryDeliverEvent(s.events, receiver.Event{Data: data}, SensorLabel, s.drops)
}

func (s *Sensor) execFromRecord(r etw.Record) ([]byte, error) {
	pid, okPID := r.Uint32("ProcessID")
	createFT, okCT := r.Int64("CreateTime")
	image := ntPathToDOS(r.UTF16String("ImageName"), s.deviceMap)
	// pid, the process-create time (the pid_epoch), and the image path are required: an event missing any of them cannot be correlated
	// or acted on, so drop it rather than emit a degenerate envelope (pid=0 / empty path / epoch=0) that would corrupt exec/exit pairing.
	if !okPID || pid == 0 || !okCT || createFT == 0 || image == "" {
		return nil, fmt.Errorf("etw exec: missing required fields (pid=%d okPID=%v createTime=%d okCT=%v image=%q)", pid, okPID, createFT, okCT, image)
	}
	ppid, _ := r.Uint32("ParentProcessID") // best-effort: not every start event carries a parent, and 0 is acceptable for root-ish procs
	return execEnvelope(uuid.NewString(), s.hostID, time.Now().UnixNano(), execPayload{
		PID:          int(pid),
		PPID:         int(ppid),
		Path:         image,
		Args:         []string{}, // command line requires a PEB read; a follow-up spike (ADR-0018).
		Cwd:          "",
		UID:          0,
		GID:          0,
		CreateTimeNs: filetimeToUnixNano(createFT),
	})
}

func (s *Sensor) exitFromRecord(r etw.Record) ([]byte, error) {
	pid, okPID := r.Uint32("ProcessID")
	createFT, okCT := r.Int64("CreateTime")
	// pid and the pid_epoch are required to pair this exit with its exec generation; without them the exit is unattributable, so drop it.
	if !okPID || pid == 0 || !okCT || createFT == 0 {
		return nil, fmt.Errorf("etw exit: missing required fields (pid=%d okPID=%v createTime=%d okCT=%v)", pid, okPID, createFT, okCT)
	}
	exitCode, _ := r.Uint32("ExitCode") // best-effort: 0 is a legitimate (success) exit code, so a missing/zero value is not fatal
	// A Windows exit code is an unsigned DWORD, but the server's shared exit_code contract is a signed INT (used by macOS too). Reinterpret
	// the DWORD as int32 so NTSTATUS/HRESULT crash codes (e.g. 0xC0000005) land in signed-int range instead of overflowing the column and
	// failing ingestion. This is bit-lossless: the raw DWORD is recoverable as uint32(int32(v)), and signed is the conventional display for
	// such codes (0xC0000005 -> -1073741819). Widening the whole path to BIGINT for unsigned display would be a separate cross-context change.
	return exitEnvelope(uuid.NewString(), s.hostID, time.Now().UnixNano(), exitPayload{
		PID:          int(pid),
		ExitCode:     int(int32(exitCode)),
		CreateTimeNs: filetimeToUnixNano(createFT),
	})
}

// Events returns the channel of mapped event envelopes.
func (s *Sensor) Events() <-chan receiver.Event { return s.events }

// Errors returns the channel on which a dropped session is signalled so the loop reconnects.
func (s *Sensor) Errors() <-chan int { return s.errs }

// Ping reports sensor liveness for the heartbeat loop: healthy while the ProcessTrace goroutine is running. The timeout is unused (the
// check is a local flag read, not a round-trip).
func (s *Sensor) Ping(_ time.Duration) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.running {
		return errors.New("wintel: ETW consumer not running")
	}
	return nil
}

// SendApplicationControl is unsupported on the driverless sensor.
func (s *Sensor) SendApplicationControl(_ []byte) error { return ErrUnsupported }

// Disconnect tears the sensor down and waits for the ProcessTrace goroutine to exit, so a subsequent Connect never overlaps a
// still-draining session. Order is load-bearing: CloseTrace is what actually unblocks a blocked ProcessTrace (it returns
// ERROR_CTX_CLOSE_PENDING and tells ProcessTrace to drain its buffers and return), so Close MUST run before the wait. Waiting first
// would deadlock if Stop() alone does not unblock ProcessTrace. Stop errors are logged but not fatal: Close still unblocks the goroutine,
// so the wait cannot hang on a failed Stop.
func (s *Sensor) Disconnect() {
	s.mu.Lock()
	sess, consumer := s.session, s.consumer
	s.session, s.consumer = nil, nil
	s.running = false
	s.mu.Unlock()
	if sess != nil {
		if err := sess.Stop(); err != nil {
			s.logger.Warn("etw stop session", "err", err)
		}
	}
	if consumer != nil {
		if err := consumer.Close(); err != nil {
			s.logger.Warn("etw close consumer", "err", err)
		}
	}
	// Close() has signalled ProcessTrace to return; now wait for the goroutine to actually exit. Do not hold s.mu here: the goroutine
	// takes it on the way out, so waiting under the lock would deadlock.
	s.wg.Wait()
}
