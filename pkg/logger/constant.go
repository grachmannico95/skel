package logger

type requestContext string
type logType string

const (
	// log severity reference: https://www.sumologic.com/glossary/log-levels/

	// Emergency assigned when an event log indicates that the system is completely unusable
	LevelEmergency int = iota
	// Alert assigned when an event log requires an immediate response, such as when a system database becomes corrupted and must be restored to prevent the loss of critical data or services
	LevelAlert
	// Critical assigned for critical errors, such as hardware failure
	LevelCritical
	// Error assigned to event logs that contain an application error message
	LevelError
	// Warning assign when an operation fails, while a warning might indicate that an operation will fail in the future if action is not taken now
	LevelWarning
	// Notice include information about events that may be unusual but are not errors
	LevelNotice
	// Info include information about successful operations within the application, such as a successful start, pause, or exit of the application
	LevelInfo
	// Debug logs typically contain information that is only useful during the debug phase and may be of little value during production
	LevelDebug
)

const (
	CtxTraceId   requestContext = "ctx_trace_id"
	CtxRequestAt requestContext = "ctx_request_at"
	CtxUserId    requestContext = "ctx_user_id"

	LogTypeSystem          logType = "system"
	LogTypeRequestResponse logType = "request-response"
)

type RequestResponseLogger struct {
	TraceID      string
	FromIP       string
	ResponseTime int64
	Path         string
	Queries      map[string][]string
	Method       string
	Headers      interface{}
	Request      interface{}
	Response     interface{}
}
