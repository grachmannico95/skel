package httpserver

import (
	"net/http"

	"github.com/labstack/echo/v4"
)

func (h *HttpServerHandler) HealthCheck(c echo.Context) error {
	return c.JSON(http.StatusOK, Resp[Success].ClearMessage().AddMessage("server up and running"))
}

func (h *HttpServerHandler) Readiness(c echo.Context) error {
	return c.String(http.StatusOK, "200 OK")
}
