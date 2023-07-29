package httpserver

import (
	"errors"
	"net/http"

	"github.com/grachmannico95/skel/internal/domain/auth"
	"github.com/grachmannico95/skel/internal/domain/user"
	"github.com/grachmannico95/skel/pkg/logger"
	"github.com/grachmannico95/skel/pkg/validator"
	"github.com/labstack/echo/v4"
)

func (h *HttpServerHandler) CreateToken(c echo.Context) error {
	type request struct {
		Username string `json:"username" validate:"required"`
		Password string `json:"password" validate:"required,min=8"`
	}

	type response struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
	}

	var req request
	var res response
	var err error
	var ctx = c.Request().Context()
	var lang = extractRequest(c.Request()).getLang()

	// bind request
	if err = c.Bind(&req); err != nil {
		logger.Info(ctx, "failed to bind request cause %v", err)
		return c.JSON(http.StatusBadRequest, Resp[Failed].AddMessage(h.Dictionary.ErrBindRequest.GetLang(lang)))
	}

	// validate request
	if err = validator.ValidateStruct(req); err != nil {
		logger.Info(ctx, "failed to validate request cause %v", err)
		return c.JSON(http.StatusBadRequest, Resp[Failed].AddMessage(h.Dictionary.ErrValidation.GetLang(lang)))
	}

	// validate user
	userData, err := h.UserService.GetByCredential(ctx, user.InputUserCredential{
		Username: req.Username,
		Password: req.Password,
	})
	if err != nil {
		logger.Info(ctx, "failed to getting user credential cause %v", err)

		if errors.Is(err, user.ErrValidation) {
			return c.JSON(http.StatusBadRequest, Resp[Failed].AddMessage(h.Dictionary.ErrValidation.GetLang(lang)))
		}
		if errors.Is(err, user.ErrNotFound) {
			return c.JSON(http.StatusNotFound, Resp[Failed].AddMessage("user").AddMessage(h.Dictionary.ErrDataNotFound.GetLang(lang)))
		}
		if errors.Is(err, user.ErrPasswordNotMatch) {
			return c.JSON(http.StatusInternalServerError, Resp[Failed].AddMessage("user's").AddMessage(h.Dictionary.ErrPasswordNotMatch.GetLang(lang)))
		}
		return c.JSON(http.StatusInternalServerError, Resp[Failed].AddMessage(h.Dictionary.Err.GetLang(lang)).AddData(err.Error()))
	}

	// create token
	token, err := h.AuthService.Generate(ctx, auth.InputGenerateToken{
		UserID: userData.ID,
	})
	if err != nil {
		logger.Info(ctx, "failed to generate auth token cause %v", err)

		if errors.Is(err, auth.ErrValidation) {
			return c.JSON(http.StatusBadRequest, Resp[Failed].AddMessage(h.Dictionary.ErrValidation.GetLang(lang)))
		}
		return c.JSON(http.StatusInternalServerError, Resp[Failed].AddMessage(h.Dictionary.Err.GetLang(lang)).AddData(err.Error()))
	}

	// construct response
	res = response{
		AccessToken:  token.AccessToken,
		RefreshToken: token.RefreshToken,
	}

	return c.JSON(http.StatusOK, Resp[Success].AddMessage(h.Dictionary.Success.GetLang(lang)).AddData(res))
}

func (h *HttpServerHandler) VerifyToken(c echo.Context) error {
	type request struct {
		Token string `validate:"required" json:"token"`
	}

	type response struct {
		Claims auth.Claims `json:"claims"`
	}

	var req request
	var res response
	var err error
	var ctx = c.Request().Context()
	var lang = extractRequest(c.Request()).getLang()

	// bind request
	if err = c.Bind(&req); err != nil {
		logger.Info(ctx, "failed to bind request cause %v", err)
		return c.JSON(http.StatusBadRequest, Resp[Failed].AddMessage(h.Dictionary.ErrBindRequest.GetLang(lang)))
	}

	// validate request
	if err = validator.ValidateStruct(req); err != nil {
		logger.Info(ctx, "failed to validate request cause %v", err)
		return c.JSON(http.StatusBadRequest, Resp[Failed].AddMessage(h.Dictionary.ErrValidation.GetLang(lang)))
	}

	// verify token
	claims, err := h.AuthService.Validate(ctx, req.Token)
	if err != nil {
		logger.Info(ctx, "failed to validate auth token cause %v", err)

		if errors.Is(err, user.ErrValidation) {
			return c.JSON(http.StatusBadRequest, Resp[Failed].AddMessage(h.Dictionary.ErrValidation.GetLang(lang)))
		}
		if errors.Is(err, auth.ErrTokenExpired) {
			return c.JSON(http.StatusUnauthorized, Resp[Failed].AddMessage(h.Dictionary.ErrTokenExpired.GetLang(lang)))
		}
		if errors.Is(err, auth.ErrTokenInvalid) {
			return c.JSON(http.StatusUnauthorized, Resp[Failed].AddMessage(h.Dictionary.ErrTokenInvalid.GetLang(lang)))
		}
		return c.JSON(http.StatusInternalServerError, Resp[Failed].AddMessage(h.Dictionary.Err.GetLang(lang)).AddData(err.Error()))
	}

	// construct response
	res = response{
		Claims: *claims,
	}

	return c.JSON(http.StatusOK, Resp[Success].AddMessage(h.Dictionary.Success.GetLang(lang)).AddData(res))
}

func (h *HttpServerHandler) RefreshToken(c echo.Context) error {
	type request struct {
		Token string `validate:"required" json:"token"`
	}

	type response struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
	}

	var req request
	var res response
	var err error
	var ctx = c.Request().Context()
	var lang = extractRequest(c.Request()).getLang()

	// bind request
	if err = c.Bind(&req); err != nil {
		logger.Info(ctx, "failed to bind request cause %v", err)
		return c.JSON(http.StatusBadRequest, Resp[Failed].AddMessage(h.Dictionary.ErrBindRequest.GetLang(lang)))
	}

	// validate request
	if err = validator.ValidateStruct(req); err != nil {
		logger.Info(ctx, "failed to validate request cause %v", err)
		return c.JSON(http.StatusBadRequest, Resp[Failed].AddMessage(h.Dictionary.ErrValidation.GetLang(lang)))
	}

	// verify token
	token, err := h.AuthService.Refresh(ctx, auth.InputRefreshToken{
		Token: res.RefreshToken,
	})
	if err != nil {
		logger.Info(ctx, "failed to refresh auth token cause %v", err)

		if errors.Is(err, user.ErrValidation) {
			return c.JSON(http.StatusBadRequest, Resp[Failed].AddMessage(h.Dictionary.ErrValidation.GetLang(lang)))
		}
		if errors.Is(err, auth.ErrTokenExpired) {
			return c.JSON(http.StatusUnauthorized, Resp[Failed].AddMessage(h.Dictionary.ErrTokenExpired.GetLang(lang)))
		}
		if errors.Is(err, auth.ErrTokenInvalid) {
			return c.JSON(http.StatusUnauthorized, Resp[Failed].AddMessage(h.Dictionary.ErrTokenInvalid.GetLang(lang)))
		}
		return c.JSON(http.StatusInternalServerError, Resp[Failed].AddMessage(h.Dictionary.Err.GetLang(lang)).AddData(err.Error()))
	}

	// construct response
	res = response{
		AccessToken:  token.AccessToken,
		RefreshToken: token.RefreshToken,
	}

	return c.JSON(http.StatusOK, Resp[Success].AddMessage(h.Dictionary.Success.GetLang(lang)).AddData(res))
}

func (h *HttpServerHandler) RevokeToken(c echo.Context) error {
	type request struct {
		ID string `validate:"required" json:"id"`
	}

	var req request
	var err error
	var ctx = c.Request().Context()
	var lang = extractRequest(c.Request()).getLang()

	// bind request
	if err = c.Bind(&req); err != nil {
		logger.Info(ctx, "failed to bind request cause %v", err)
		return c.JSON(http.StatusBadRequest, Resp[Failed].AddMessage(h.Dictionary.ErrBindRequest.GetLang(lang)))
	}

	// validate request
	if err = validator.ValidateStruct(req); err != nil {
		logger.Info(ctx, "failed to validate request cause %v", err)
		return c.JSON(http.StatusBadRequest, Resp[Failed].AddMessage(h.Dictionary.ErrValidation.GetLang(lang)))
	}

	// verify token
	err = h.AuthService.Revoke(ctx, req.ID)
	if err != nil {
		logger.Info(ctx, "failed to revoke auth cause %v", err)

		return c.JSON(http.StatusInternalServerError, Resp[Failed].AddMessage(h.Dictionary.Err.GetLang(lang)).AddData(err.Error()))
	}

	return c.JSON(http.StatusOK, Resp[Success].AddMessage(h.Dictionary.Success.GetLang(lang)))
}
