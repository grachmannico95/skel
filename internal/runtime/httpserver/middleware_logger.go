package httpserver

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"time"

	"github.com/google/uuid"
	"github.com/grachmannico95/skel/pkg/logger"
	"github.com/labstack/echo/v4"
)

func (h *HttpServerHandler) middlewareLogger(next echo.HandlerFunc) echo.HandlerFunc {
	return func(c echo.Context) error {
		var request = c.Request()
		var ctx = request.Context()

		reqBodyBytes := []byte{}
		reqBody := make(map[string]interface{})
		if c.Request().Body != nil { // Read
			reqBodyBytes, _ = io.ReadAll(c.Request().Body)
		}
		c.Request().Body = io.NopCloser(bytes.NewBuffer(reqBodyBytes)) // Reset
		if len(reqBodyBytes) > 0 {
			err := json.Unmarshal(reqBodyBytes, &reqBody)
			if err != nil {
				logger.Error(ctx, "failed to unmarshal request body cause %v", err)
			}
			reqBody = maskValue(reqBody)
			reqBodyBytes, err = json.Marshal(reqBody)
			if err != nil {
				logger.Error(ctx, "failed to marshal request body cause %v", err)
			}
		}

		skipParams := skipParams{
			method:      request.Method,
			path:        request.URL.Path,
			paramNames:  c.ParamNames(),
			paramValues: c.ParamValues(),
		}
		if h.isSkipped(middlewareLogger, skipParams) {
			return next(c)
		}

		traceID := uuid.New().String()
		requestAt := time.Now()

		ctx = context.WithValue(ctx, logger.CtxTraceId, traceID)
		ctx = context.WithValue(ctx, logger.CtxRequestAt, requestAt)
		r := request.WithContext(ctx)
		c.SetRequest(r)

		logger.Info(ctx, "[start] request from %v %v %v", skipParams.method, skipParams.path, string(reqBodyBytes))
		return next(c)
	}
}

func (h *HttpServerHandler) middlewareStalk(c echo.Context, reqBody, resBody []byte) {
	var request = c.Request()
	var ctx = c.Request().Context()

	skipParams := skipParams{
		method:      request.Method,
		path:        request.URL.Path,
		paramNames:  c.ParamNames(),
		paramValues: c.ParamValues(),
	}
	if h.isSkipped(middlewareLogger, skipParams) {
		return
	}

	var err error
	var req map[string]interface{}
	var res map[string]interface{}
	var traceID = ctx.Value(logger.CtxTraceId).(string)
	var requestAt = ctx.Value(logger.CtxRequestAt).(time.Time)
	var now = time.Now()
	var rt = now.Sub(requestAt).Milliseconds()

	if len(reqBody) > 0 {
		err = json.Unmarshal(reqBody, &req)
		if err != nil {
			logger.Error(ctx, "failed to unmarshal request body cause %v", err)
		}
	}
	if len(resBody) > 0 {
		err = json.Unmarshal(resBody, &res)
		if err != nil {
			logger.Error(ctx, "failed to unmarshal response body cause %v", err)
		}
	}

	logger.Info(ctx, "[finish] request from %v %v, response: %v", skipParams.method, skipParams.path, string(resBody))

	logger.RequestResponse(ctx, logger.RequestResponseLogger{
		TraceID:      traceID,
		FromIP:       c.RealIP(),
		ResponseTime: rt,
		Path:         c.Request().URL.Path,
		Queries:      c.Request().URL.Query(),
		Method:       c.Request().Method,
		Headers:      c.Request().Header,
		Request:      maskValue(req),
		Response:     res,
	})
}

// ***

var mask = map[string]string{
	"password": "xxx",
	"pin":      "xxxxxx",
}

func maskValue(obj map[string]interface{}) map[string]interface{} {
	for k := range obj {
		if mask[k] != "" {
			obj[k] = mask[k]
		}
	}
	return obj
}
