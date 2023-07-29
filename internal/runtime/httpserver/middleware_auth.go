package httpserver

import (
	"context"
	"errors"
	"net/http"

	"github.com/grachmannico95/skel/internal/domain/auth"
	"github.com/grachmannico95/skel/pkg/logger"
	"github.com/labstack/echo/v4"
)

// MiddlewareAuth: authentication middleware
func (h *HttpServerHandler) middlewareAuth(next echo.HandlerFunc) echo.HandlerFunc {
	return func(c echo.Context) error {
		var request = c.Request()
		var ctx = request.Context()
		var httpRequest = extractRequest(c.Request())
		var lang = httpRequest.getLang()
		var authorizationToken = httpRequest.getAuthorization()

		skipParams := skipParams{
			method:      request.Method,
			path:        request.URL.Path,
			paramNames:  c.ParamNames(),
			paramValues: c.ParamValues(),
		}
		if h.isSkipped(middlewareAuth, skipParams) {
			return next(c)
		}

		claims, err := h.AuthService.Validate(ctx, authorizationToken)
		if err != nil {
			if errors.Is(err, auth.ErrTokenExpired) {
				return c.JSON(http.StatusUnauthorized, Resp[Failed].AddMessage(h.Dictionary.ErrTokenExpired.GetLang(lang)))
			}
			if errors.Is(err, auth.ErrTokenInvalid) {
				return c.JSON(http.StatusUnauthorized, Resp[Failed].AddMessage(h.Dictionary.ErrTokenInvalid.GetLang(lang)))
			}
			return c.JSON(http.StatusUnauthorized, Resp[Failed].AddMessage(h.Dictionary.ErrUnauthenticated.GetLang(lang)))
		}

		ctx = context.WithValue(ctx, logger.CtxUserId, claims.UserID)
		r := request.WithContext(ctx)
		c.SetRequest(r)

		return next(c)
	}
}
