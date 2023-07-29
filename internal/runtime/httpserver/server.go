package httpserver

import (
	"context"
	"fmt"
	"net/http"

	"github.com/grachmannico95/skel/internal/config"
	"github.com/grachmannico95/skel/internal/domain/auth"
	"github.com/grachmannico95/skel/internal/domain/user"
	"github.com/grachmannico95/skel/pkg/logger"
	"github.com/grachmannico95/skel/pkg/validator"
	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
)

type HttpServer interface {
	Run() (err error)
	Stop(ctx context.Context) (err error)
}

type HttpServerHandler struct {
	UserService user.UserService `validate:"required"`
	AuthService auth.AuthService `validate:"required"`

	Dictionary config.AppDictionary `validate:"required"`

	skipMiddleware skipMiddleware
}

// ==================================================
// implementing echo framework as http server runtime
// ==================================================

type httpServerEcho struct {
	engine  *echo.Echo
	port    string
	handler HttpServerHandler
}

func NewHttpServerEcho(port string, handler HttpServerHandler) (httpServer HttpServer, err error) {
	if err = validator.ValidateStruct(handler); err != nil {
		return
	}

	httpServer = &httpServerEcho{
		engine:  echo.New(),
		port:    port,
		handler: handler,
	}
	return
}

func (s *httpServerEcho) Run() (err error) {
	// middleware
	s.setupMiddleware()

	// route
	s.setupRoute()

	// error handler
	s.engine.HTTPErrorHandler = s.handler.errorHandler

	// start http server
	if err = s.engine.Start(fmt.Sprintf(":%s", s.port)); err != nil {
		return
	}

	return
}

func (s *httpServerEcho) Stop(ctx context.Context) (err error) {
	if err = s.engine.Shutdown(ctx); err != nil {
		return
	}
	return
}

// ***

func (s *httpServerEcho) setupMiddleware() {
	// remove trailing slash
	s.engine.Pre(middleware.RemoveTrailingSlash())

	// cors
	s.engine.Use(middleware.CORS())

	// middleware logger
	s.engine.Use(s.handler.middlewareLogger)

	// middleware auth
	s.engine.Use(s.handler.middlewareAuth)

	// middleware stalk request and response
	s.engine.Use(middleware.BodyDump(s.handler.middlewareStalk))

	// skip middleware
	s.handler.skip(middlewareLogger, http.MethodGet, "/")
	s.handler.skip(middlewareLogger, http.MethodGet, "/health-check")

	s.handler.skip(middlewareAuth, http.MethodGet, "/")
	s.handler.skip(middlewareAuth, http.MethodGet, "/health-check")
	s.handler.skip(middlewareAuth, http.MethodPost, "/auth/create-token")
	s.handler.skip(middlewareAuth, http.MethodPost, "/auth/verify-token")
	s.handler.skip(middlewareAuth, http.MethodPost, "/auth/refresh-token")
	s.handler.skip(middlewareAuth, http.MethodPost, "/auth/revoke-token")
	s.handler.skip(middlewareAuth, http.MethodGet, "/user/:id")
	s.handler.skip(middlewareAuth, http.MethodPost, "/user")

	s.engine.Use(middleware.Recover())
}

func (s *httpServerEcho) setupRoute() {
	s.engine.GET("", s.handler.Readiness)
	s.engine.GET("/health-check", s.handler.HealthCheck)

	rAuth := s.engine.Group("/auth")
	rAuth.POST("/create-token", s.handler.CreateToken)
	rAuth.POST("/verify-token", s.handler.VerifyToken)
	rAuth.POST("/refresh-token", s.handler.RefreshToken)
	rAuth.POST("/revoke-token", s.handler.RevokeToken)

	rUser := s.engine.Group("/user")
	rUser.GET("/:id", s.handler.GetUser)
	rUser.POST("", s.handler.CreateUser)
	rUser.POST("/change-username", s.handler.ChangeUsername)
	rUser.POST("/change-name", s.handler.ChangeName)
	rUser.POST("/change-password", s.handler.ChangePassword)
	rUser.DELETE("/:id", s.handler.DeactivateUser)
}

func (h *HttpServerHandler) errorHandler(err error, c echo.Context) {
	var lang = extractRequest(c.Request()).getLang()

	report, ok := err.(*echo.HTTPError)
	if !ok {
		report = echo.NewHTTPError(http.StatusInternalServerError, err.Error())
	}

	var errMessage config.DictionaryKey
	switch report.Code {
	case http.StatusBadRequest:
		errMessage = h.Dictionary.ErrTokenInvalid
	case http.StatusUnauthorized:
		errMessage = h.Dictionary.ErrUnauthenticated
	case http.StatusForbidden:
		errMessage = h.Dictionary.ErrUnauthorized
	case http.StatusNotFound:
		errMessage = h.Dictionary.ErrDataNotFound
	case http.StatusInternalServerError:
		errMessage = h.Dictionary.Err
	default:
		errMessage = h.Dictionary.Err
	}

	logger.Error(c.Request().Context(), "panic recovered. error cause %v", err)

	c.JSON(report.Code, Resp[Failed].AddMessage(errMessage.GetLang(lang)))
}
