package logger

import (
	"context"
)

type Logger interface {
	Debug(ctx context.Context, message string, args ...interface{})
	Info(ctx context.Context, message string, args ...interface{})
	Warn(ctx context.Context, message string, args ...interface{})
	Error(ctx context.Context, message string, args ...interface{})
	Fatal(ctx context.Context, message string, args ...interface{})
	RequestResponse(ctx context.Context, requestResponse RequestResponseLogger)
}

// ***

type loggerInstance struct {
	engine        Logger
	severityLevel int
}

var logger loggerInstance

func log() *loggerInstance {
	if logger.engine == nil {
		logger.engine = newLoggerZeroLog(logger.severityLevel) // you can change whatever logger implementation
	}

	return &logger
}

// ***

func SetSeverityLevel(level int) {
	logger = loggerInstance{
		engine:        nil,
		severityLevel: level,
	}
}

func Debug(ctx context.Context, message string, args ...interface{}) {
	log().engine.Debug(ctx, message, args...)
}

func Info(ctx context.Context, message string, args ...interface{}) {
	log().engine.Info(ctx, message, args...)
}

func Warn(ctx context.Context, message string, args ...interface{}) {
	log().engine.Warn(ctx, message, args...)
}

func Error(ctx context.Context, message string, args ...interface{}) {
	log().engine.Error(ctx, message, args...)
}

func Fatal(ctx context.Context, message string, args ...interface{}) {
	log().engine.Fatal(ctx, message, args...)
}

func RequestResponse(ctx context.Context, requestResponse RequestResponseLogger) {
	log().engine.RequestResponse(ctx, requestResponse)
}
