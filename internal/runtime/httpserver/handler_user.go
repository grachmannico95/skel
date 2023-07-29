package httpserver

import (
	"errors"
	"net/http"
	"time"

	"github.com/grachmannico95/skel/internal/domain/user"
	"github.com/grachmannico95/skel/pkg/logger"
	"github.com/grachmannico95/skel/pkg/validator"
	"github.com/labstack/echo/v4"
)

func (h *HttpServerHandler) GetUser(c echo.Context) error {
	type request struct {
		ID string `param:"id" validate:"required"`
	}

	type response struct {
		ID        string `json:"id"`
		Username  string `json:"username"`
		Name      string `json:"name"`
		CreatedAt string `json:"created_at"`
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

	// find user by identifier
	userData, err := h.UserService.GetByIdentifier(ctx, user.InputUserIdentifier{
		ID: req.ID,
	})
	if err != nil {
		logger.Info(ctx, "failed to get user by identifier cause %v", err)

		if errors.Is(err, user.ErrValidation) {
			return c.JSON(http.StatusBadRequest, Resp[Failed].AddMessage(h.Dictionary.ErrValidation.GetLang(lang)))
		}
		if errors.Is(err, user.ErrNotFound) {
			return c.JSON(http.StatusNotFound, Resp[Failed].AddMessage("user").AddMessage(h.Dictionary.ErrDataNotFound.GetLang(lang)))
		}
		return c.JSON(http.StatusInternalServerError, Resp[Failed].AddMessage(h.Dictionary.ErrValidation.GetLang(lang)))
	}

	// construct response
	res = response{
		ID:        userData.ID,
		Username:  userData.Username,
		Name:      userData.Name,
		CreatedAt: userData.CreatedAt.Format("2006-01-02 15:04:05"),
	}

	return c.JSON(http.StatusOK, Resp[Success].AddMessage(h.Dictionary.Success.GetLang("en")).AddData(res))
}

func (h *HttpServerHandler) CreateUser(c echo.Context) error {
	type request struct {
		Username string `json:"username" validate:"required"`
		Name     string `json:"name" validate:"required"`
		Password string `json:"password" validate:"required,min=8"`
	}

	type response struct {
		ID        string `json:"id"`
		Username  string `json:"username"`
		Name      string `json:"name"`
		CreatedAt string `json:"created_at"`
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

	// find user by identifier
	userData, err := h.UserService.Create(ctx, user.InputCreateUser{
		Username: req.Username,
		Name:     req.Name,
		Password: req.Password,
	})
	if err != nil {
		logger.Info(ctx, "failed to create user cause %v", err)

		if errors.Is(err, user.ErrValidation) {
			return c.JSON(http.StatusBadRequest, Resp[Failed].AddMessage(h.Dictionary.ErrValidation.GetLang(lang)))
		}
		if errors.Is(err, user.ErrUsernameAlreadyUsed) {
			return c.JSON(http.StatusInternalServerError, Resp[Failed].AddMessage("username").AddMessage(h.Dictionary.ErrDataAlreadyUsed.GetLang(lang)))
		}
		return c.JSON(http.StatusInternalServerError, Resp[Failed].AddMessage(h.Dictionary.Err.GetLang(lang)).AddData(err.Error()))
	}

	// construct response
	res = response{
		ID:        userData.ID,
		Username:  userData.Username,
		Name:      userData.Name,
		CreatedAt: userData.CreatedAt.Format("2006-01-02 15:04:05"),
	}

	return c.JSON(http.StatusOK, Resp[Success].AddMessage(h.Dictionary.Success.GetLang(lang)).AddData(res))
}

func (h *HttpServerHandler) ChangeUsername(c echo.Context) error {
	type request struct {
		ID       string `json:"id" validate:"required"`
		Username string `json:"username" validate:"required"`
	}

	type response struct {
		ID        string `json:"id"`
		Username  string `json:"username"`
		Name      string `json:"name"`
		CreatedAt string `json:"created_at"`
	}

	var req request
	var res response
	var err error
	var ctx = c.Request().Context()
	var lang = extractRequest(c.Request()).getLang()
	var userId = ctx.Value(logger.CtxUserId)
	var timeNow = time.Now()

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

	// check is an authorized access
	if userId != req.ID {
		logger.Info(ctx, "failed to authorize request, unmatched between userId (%v) compare to reqId (%v)", userId, req.ID)
		return c.JSON(http.StatusForbidden, Resp[Failed].AddMessage(h.Dictionary.ErrUnauthorized.GetLang(lang)))
	}

	// find user by identifier
	userData, err := h.UserService.ChangeUsername(ctx, user.InputChangeUsername{
		ID:        req.ID,
		Username:  req.Username,
		UpdatedAt: &timeNow,
	})
	if err != nil {
		logger.Info(ctx, "failed to change username cause %v", err)

		if errors.Is(err, user.ErrValidation) {
			return c.JSON(http.StatusBadRequest, Resp[Failed].AddMessage(h.Dictionary.ErrValidation.GetLang(lang)))
		}
		if errors.Is(err, user.ErrNotFound) {
			return c.JSON(http.StatusInternalServerError, Resp[Failed].AddMessage("user").AddMessage(h.Dictionary.ErrDataNotFound.GetLang(lang)))
		}
		if errors.Is(err, user.ErrUsernameAlreadyUsed) {
			return c.JSON(http.StatusInternalServerError, Resp[Failed].AddMessage("username").AddMessage(h.Dictionary.ErrDataAlreadyUsed.GetLang(lang)))
		}
		return c.JSON(http.StatusInternalServerError, Resp[Failed].AddMessage(h.Dictionary.Err.GetLang(lang)).AddData(err.Error()))
	}

	// construct response
	res = response{
		ID:        userData.ID,
		Username:  userData.Username,
		Name:      userData.Name,
		CreatedAt: userData.CreatedAt.Format("2006-01-02 15:04:05"),
	}

	return c.JSON(http.StatusOK, Resp[Success].AddMessage(h.Dictionary.Success.GetLang(lang)).AddData(res))
}

func (h *HttpServerHandler) ChangeName(c echo.Context) error {
	type request struct {
		ID   string `json:"id" validate:"required"`
		Name string `json:"name" validate:"required"`
	}

	type response struct {
		ID        string `json:"id"`
		Username  string `json:"username"`
		Name      string `json:"name"`
		CreatedAt string `json:"created_at"`
	}

	var req request
	var res response
	var err error
	var ctx = c.Request().Context()
	var lang = extractRequest(c.Request()).getLang()
	var userId = ctx.Value(logger.CtxUserId)
	var timeNow = time.Now()

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

	// check is an authorized access
	if userId != req.ID {
		logger.Info(ctx, "failed to authorize request, unmatched between userId (%v) compare to reqId (%v)", userId, req.ID)
		return c.JSON(http.StatusForbidden, Resp[Failed].AddMessage(h.Dictionary.ErrUnauthorized.GetLang(lang)))
	}

	// find user by identifier
	userData, err := h.UserService.ChangeName(ctx, user.InputChangeName{
		ID:        req.ID,
		Name:      req.Name,
		UpdatedAt: &timeNow,
	})
	if err != nil {
		logger.Info(ctx, "failed to change name cause %v", err)

		if errors.Is(err, user.ErrValidation) {
			return c.JSON(http.StatusBadRequest, Resp[Failed].AddMessage(h.Dictionary.ErrValidation.GetLang(lang)))
		}
		if errors.Is(err, user.ErrNotFound) {
			return c.JSON(http.StatusNotFound, Resp[Failed].AddMessage("user").AddMessage(h.Dictionary.ErrDataNotFound.GetLang(lang)))
		}
		return c.JSON(http.StatusInternalServerError, Resp[Failed].AddMessage(h.Dictionary.Err.GetLang(lang)).AddData(err.Error()))
	}

	// construct response
	res = response{
		ID:        userData.ID,
		Username:  userData.Username,
		Name:      userData.Name,
		CreatedAt: userData.CreatedAt.Format("2006-01-02 15:04:05"),
	}

	return c.JSON(http.StatusOK, Resp[Success].AddMessage(h.Dictionary.Success.GetLang(lang)).AddData(res))
}

func (h *HttpServerHandler) ChangePassword(c echo.Context) error {
	type request struct {
		ID          string `json:"id" validate:"required"`
		OldPassword string `json:"old_password" validate:"required,min=8"`
		NewPassword string `json:"new_password" validate:"required,min=8"`
	}

	type response struct {
		ID        string `json:"id"`
		Username  string `json:"username"`
		Name      string `json:"name"`
		CreatedAt string `json:"created_at"`
	}

	var req request
	var res response
	var err error
	var ctx = c.Request().Context()
	var lang = extractRequest(c.Request()).getLang()
	var userId = ctx.Value(logger.CtxUserId)
	var timeNow = time.Now()

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

	// check is an authorized access
	if userId != req.ID {
		logger.Info(ctx, "failed to authorize request, unmatched between userId (%v) compare to reqId (%v)", userId, req.ID)
		return c.JSON(http.StatusForbidden, Resp[Failed].AddMessage(h.Dictionary.ErrUnauthorized.GetLang(lang)))
	}

	// find user by identifier
	userData, err := h.UserService.ChangePassword(ctx, user.InputChangePassword{
		ID:          req.ID,
		OldPassword: req.OldPassword,
		NewPassword: req.NewPassword,
		UpdatedAt:   &timeNow,
	})
	if err != nil {
		logger.Info(ctx, "failed to change password cause %v", err)

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

	// construct response
	res = response{
		ID:        userData.ID,
		Username:  userData.Username,
		Name:      userData.Name,
		CreatedAt: userData.CreatedAt.Format("2006-01-02 15:04:05"),
	}

	return c.JSON(http.StatusOK, Resp[Success].AddMessage(h.Dictionary.Success.GetLang(lang)).AddData(res))
}

func (h *HttpServerHandler) DeactivateUser(c echo.Context) error {
	type request struct {
		ID string `param:"id" validate:"required"`
	}

	type response struct {
		ID        string `json:"id"`
		Username  string `json:"username"`
		Name      string `json:"name"`
		CreatedAt string `json:"created_at"`
	}

	var req request
	var res response
	var err error
	var ctx = c.Request().Context()
	var lang = extractRequest(c.Request()).getLang()
	var userId = ctx.Value(logger.CtxUserId)
	var timeNow = time.Now()

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

	// check is an authorized access
	if userId != req.ID {
		logger.Info(ctx, "failed to authorize request, unmatched between userId (%v) compare to reqId (%v)", userId, req.ID)
		return c.JSON(http.StatusForbidden, Resp[Failed].AddMessage(h.Dictionary.ErrUnauthorized.GetLang(lang)))
	}

	// find user by identifier
	userData, err := h.UserService.Deactivate(ctx, user.InputDeactivate{
		ID:        req.ID,
		UpdatedAt: &timeNow,
	})
	if err != nil {
		logger.Info(ctx, "failed to deactivate user cause %v", err)

		if errors.Is(err, user.ErrValidation) {
			return c.JSON(http.StatusBadRequest, Resp[Failed].AddMessage(h.Dictionary.ErrValidation.GetLang(lang)))
		}
		if errors.Is(err, user.ErrNotFound) {
			return c.JSON(http.StatusNotFound, Resp[Failed].AddMessage("user").AddMessage(h.Dictionary.ErrDataNotFound.GetLang(lang)))
		}
		return c.JSON(http.StatusInternalServerError, Resp[Failed].AddMessage(h.Dictionary.ErrValidation.GetLang(lang)))
	}

	// construct response
	res = response{
		ID:        userData.ID,
		Username:  userData.Username,
		Name:      userData.Name,
		CreatedAt: userData.CreatedAt.Format("2006-01-02 15:04:05"),
	}

	return c.JSON(http.StatusOK, Resp[Success].AddMessage(h.Dictionary.Success.GetLang("en")).AddData(res))
}
