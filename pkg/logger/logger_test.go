package logger_test

import (
	"context"
	"testing"

	"github.com/grachmannico95/skel/pkg/logger"
)

func TestLogger(t *testing.T) {
	ctx := context.Background()

	// without value
	logger.SetSeverityLevel(logger.LevelInfo)
	logger.Info(ctx, "log without context")

	// with context
	ctx = context.WithValue(ctx, logger.CtxTraceId, "1234")
	logger.Info(ctx, "log with context")

	// change context value
	ctx = context.WithValue(ctx, logger.CtxTraceId, "4321")
	logger.Info(ctx, "log with context -- value changed")

	// set severity level to critical
	logger.SetSeverityLevel(logger.LevelError)
	logger.Info(ctx, "this log should not be printed")
	logger.Error(ctx, "this log should be printed")

	// set severity level back to info
	logger.SetSeverityLevel(logger.LevelInfo)
	logger.Info(ctx, "after changed to level info, this log should be printed")
	logger.Error(ctx, "after changed to level info, this log should be printed too")
}
