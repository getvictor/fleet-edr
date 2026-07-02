//go:build windows

package etw

import "golang.org/x/sys/windows"

// ETW control and mode constants (Microsoft ETW docs). Only the ones the real-time Kernel-Process consumer needs are defined.
const (
	wnodeFlagTracedGUID       = 0x00020000 // WNODE_FLAG_TRACED_GUID
	eventTraceRealTimeMode    = 0x00000100 // EVENT_TRACE_REAL_TIME_MODE
	processTraceModeRealTime  = 0x00000100 // PROCESS_TRACE_MODE_REAL_TIME
	processTraceModeEventRec  = 0x10000000 // PROCESS_TRACE_MODE_EVENT_RECORD
	eventControlCodeEnable    = 1          // EVENT_CONTROL_CODE_ENABLE_PROVIDER
	traceLevelInformation     = 4          // TRACE_LEVEL_INFORMATION
	eventTraceControlStop     = 1          // EVENT_TRACE_CONTROL_STOP
	clientContextQPC          = 1          // WNODE_HEADER.ClientContext: QueryPerformanceCounter timestamps
	invalidProcessTraceHandle = ^uintptr(0)
)

// wnodeHeader is WNODE_HEADER: the leading member of EVENT_TRACE_PROPERTIES. Union members are represented by their widest arm
// (HistoricalContext as ULONG64, TimeStamp as LARGE_INTEGER/int64) so the field offsets match the C layout exactly.
type wnodeHeader struct {
	BufferSize        uint32
	ProviderID        uint32
	HistoricalContext uint64
	TimeStamp         int64
	Guid              windows.GUID
	ClientContext     uint32
	Flags             uint32
}

// eventTraceProperties is EVENT_TRACE_PROPERTIES. A session is started by allocating a byte buffer sized for this struct plus the
// logger-name string, casting the head to this type, and pointing LoggerNameOffset just past the struct.
type eventTraceProperties struct {
	Wnode               wnodeHeader
	BufferSize          uint32
	MinimumBuffers      uint32
	MaximumBuffers      uint32
	MaximumFileSize     uint32
	LogFileMode         uint32
	FlushTimer          uint32
	EnableFlags         uint32
	AgeLimit            int32
	NumberOfBuffers     uint32
	FreeBuffers         uint32
	EventsLost          uint32
	BuffersWritten      uint32
	LogBuffersLost      uint32
	RealTimeBuffersLost uint32
	LoggerThreadID      uintptr
	LogFileNameOffset   uint32
	LoggerNameOffset    uint32
}

// eventTraceHeader is EVENT_TRACE_HEADER, embedded in EVENT_TRACE. Its size is load-bearing: it sits ahead of the callback pointer in
// EVENT_TRACE_LOGFILEW, so a wrong layout silently yields zero delivered events.
type eventTraceHeader struct {
	Size          uint16
	FieldTypeFlag uint16
	Version       uint32
	ThreadID      uint32
	ProcessID     uint32
	TimeStamp     int64
	Guid          windows.GUID
	ClientContext uint32
	Flags         uint32
}

// eventTrace is EVENT_TRACE (the CurrentEvent member of EVENT_TRACE_LOGFILEW).
type eventTrace struct {
	Header           eventTraceHeader
	InstanceID       uint32
	ParentInstanceID uint32
	ParentGuid       windows.GUID
	MofData          uintptr
	MofLength        uint32
	BufferContext    uint32
}

// traceLogfileHeader is TRACE_LOGFILE_HEADER (the LogfileHeader member of EVENT_TRACE_LOGFILEW). Only its overall size/layout matters
// to the consumer: it precedes the callback pointer, so the field set must match the C struct.
type traceLogfileHeader struct {
	BufferSize         uint32
	Version            uint32
	ProviderVersion    uint32
	NumberOfProcessors uint32
	EndTime            int64
	TimerResolution    uint32
	MaximumFileSize    uint32
	LogFileMode        uint32
	BuffersWritten     uint32
	StartBuffers       uint32
	PointerSize        uint32
	EventsLost         uint32
	CPUSpeedInMHz      uint32
	LoggerName         uintptr
	LogFileName        uintptr
	TimeZone           windows.Timezoneinformation
	BootTime           int64
	PerfFreq           int64
	StartTime          int64
	ReservedFlags      uint32
	BuffersLost        uint32
}

// eventTraceLogfile is EVENT_TRACE_LOGFILEW, passed to OpenTraceW. Callback holds the EVENT_RECORD callback (union arm selected by the
// PROCESS_TRACE_MODE_EVENT_RECORD flag in ProcessTraceMode).
type eventTraceLogfile struct {
	LogFileName      *uint16
	LoggerName       *uint16
	CurrentTime      int64
	BuffersRead      uint32
	ProcessTraceMode uint32
	CurrentEvent     eventTrace
	LogfileHeader    traceLogfileHeader
	BufferCallback   uintptr
	BufferSize       uint32
	Filled           uint32
	EventsLost       uint32
	Callback         uintptr
	IsKernelTrace    uint32
	Context          uintptr
}

// eventDescriptor is EVENT_DESCRIPTOR: the manifest identity of an event. ID discriminates ProcessStart (1) from ProcessStop (2).
type eventDescriptor struct {
	ID      uint16
	Version uint8
	Channel uint8
	Level   uint8
	Opcode  uint8
	Task    uint16
	Keyword uint64
}

// eventHeader is EVENT_HEADER. Only the fields up to EventDescriptor are read from Go; TDH reads the full native record via the
// EVENT_RECORD pointer, so the trailing union (timestamps, activity id) is intentionally omitted here.
type eventHeader struct {
	Size            uint16
	HeaderType      uint16
	Flags           uint16
	EventProperty   uint16
	ThreadID        uint32
	ProcessID       uint32
	TimeStamp       int64
	ProviderID      windows.GUID
	EventDescriptor eventDescriptor
}

// eventRecord is the head of EVENT_RECORD. The callback receives a pointer to the full native struct; this partial view exposes the
// header, and TdhGetProperty reads the rest (BufferContext, UserData, ...) natively from the same pointer.
type eventRecord struct {
	EventHeader eventHeader
}

// propertyDataDescriptor is PROPERTY_DATA_DESCRIPTOR. PropertyName holds a pointer to the UTF-16 property name (ULONGLONG in C).
type propertyDataDescriptor struct {
	PropertyName uint64
	ArrayIndex   uint32
	Reserved     uint32
}
