//go:build windows

package wintel

import (
	"errors"
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

	mu        sync.Mutex
	session   *etw.Session
	consumer  *etw.Consumer
	deviceMap map[string]string
	running   bool
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

	go func() {
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
// Events() buffer drops the event with a warning rather than stalling the trace (which would lose events kernel-side anyway).
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
	select {
	case s.events <- receiver.Event{Data: data}:
	default:
		s.logger.Warn("etw event dropped: buffer full")
	}
}

func (s *Sensor) execFromRecord(r etw.Record) ([]byte, error) {
	pid, _ := r.Uint32("ProcessID")
	ppid, _ := r.Uint32("ParentProcessID")
	createFT, _ := r.Int64("CreateTime")
	image := ntPathToDOS(r.UTF16String("ImageName"), s.deviceMap)
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
	pid, _ := r.Uint32("ProcessID")
	exitCode, _ := r.Uint32("ExitCode")
	createFT, _ := r.Int64("CreateTime")
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

// Disconnect stops the session (which unblocks ProcessTrace) and closes the consumer.
func (s *Sensor) Disconnect() {
	s.mu.Lock()
	sess, consumer := s.session, s.consumer
	s.session, s.consumer = nil, nil
	s.running = false
	s.mu.Unlock()
	if sess != nil {
		_ = sess.Stop()
	}
	if consumer != nil {
		_ = consumer.Close()
	}
}
