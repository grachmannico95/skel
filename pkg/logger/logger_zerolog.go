package logger

import (
	"context"
	"os"

	"github.com/rs/zerolog"
)

type loggerZeroLog struct {
	logger *zerolog.Logger
}

func newLoggerZeroLog(level int) *loggerZeroLog {
	var zeroLogLevel zerolog.Level

	switch level {
	case LevelEmergency:
		zeroLogLevel = zerolog.FatalLevel
	case LevelAlert:
		zeroLogLevel = zerolog.ErrorLevel
	case LevelCritical:
		zeroLogLevel = zerolog.ErrorLevel
	case LevelError:
		zeroLogLevel = zerolog.ErrorLevel
	case LevelWarning:
		zeroLogLevel = zerolog.WarnLevel
	case LevelNotice:
		zeroLogLevel = zerolog.InfoLevel
	case LevelInfo:
		zeroLogLevel = zerolog.InfoLevel
	case LevelDebug:
		zeroLogLevel = zerolog.DebugLevel
	default:
		zeroLogLevel = zerolog.InfoLevel
	}

	zerolog.SetGlobalLevel(zeroLogLevel)
	log := zerolog.New(os.Stdout).With().Timestamp().Logger()

	return &loggerZeroLog{
		logger: &log,
	}
}

func (l *loggerZeroLog) Debug(ctx context.Context, message string, args ...interface{}) {
	l.print(ctx, l.logger.Debug(), message, args...)
}

func (l *loggerZeroLog) Info(ctx context.Context, message string, args ...interface{}) {
	l.print(ctx, l.logger.Info(), message, args...)
}

func (l *loggerZeroLog) Warn(ctx context.Context, message string, args ...interface{}) {
	l.print(ctx, l.logger.Warn(), message, args...)
}

func (l *loggerZeroLog) Error(ctx context.Context, message string, args ...interface{}) {
	l.print(ctx, l.logger.Error(), message, args...)
}

func (l *loggerZeroLog) Fatal(ctx context.Context, message string, args ...interface{}) {
	l.print(ctx, l.logger.Fatal(), message, args...)
	os.Exit(1)
}

func (l *loggerZeroLog) RequestResponse(ctx context.Context, requestResponse RequestResponseLogger) {
	log := l.logger.Info()

	log.Any("log_type", LogTypeRequestResponse)

	log.Any("trace_id", requestResponse.TraceID)
	log.Any("from_ip", requestResponse.FromIP)
	log.Any("rt", requestResponse.ResponseTime)
	log.Any("path", requestResponse.Path)
	log.Any("queries", requestResponse.Queries)
	log.Any("method", requestResponse.Method)
	log.Any("headers", requestResponse.Headers)
	log.Any("request", requestResponse.Request)
	log.Any("response", requestResponse.Response)

	log.Send()
}

// ***

func (l *loggerZeroLog) print(ctx context.Context, log *zerolog.Event, message string, args ...interface{}) {
	l.injectFromContext(ctx, log)

	log.Any("log_type", LogTypeSystem)

	if len(args) == 0 {
		log.Msg(message)
	} else {
		log.Msgf(message, args...)
	}
}

func (l *loggerZeroLog) injectFromContext(ctx context.Context, log *zerolog.Event) *zerolog.Event {
	if ctx.Value(CtxTraceId) != nil {
		log.Any("trace_id", ctx.Value(CtxTraceId).(string))
	}

	return log
}
