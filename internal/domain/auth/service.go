package auth

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/grachmannico95/skel/pkg/logger"
	"github.com/grachmannico95/skel/pkg/validator"
)

type service struct {
	authRepo   AuthRepo
	tokenMaker TokenMaker
	cfg        Config
}

func NewService(authRepo AuthRepo, tokenMaker TokenMaker, cfg Config) (svc AuthService, err error) {
	if err = validator.ValidateStruct(cfg); err != nil {
		err = ErrValidation
		return
	}

	return &service{
		authRepo:   authRepo,
		tokenMaker: tokenMaker,
		cfg:        cfg,
	}, nil
}

// Generate: generate access and refresh token
func (s *service) Generate(ctx context.Context, in InputGenerateToken) (authToken Auth, err error) {
	// validate input
	if err = validator.ValidateStruct(in); err != nil {
		logger.Error(ctx, "error while validating input cause %v", err)
		err = ErrValidation
		return
	}

	// define issued at
	iat := time.Now()
	if !in.Opts.Time.Equal(time.Time{}) {
		iat = in.Opts.Time
	}

	// define claims for access token
	accessTokenID := uuid.New().String()
	if in.Opts.AccessTokenID != "" {
		accessTokenID = in.Opts.AccessTokenID
	}
	accessTokenClaims := Claims{
		ID:     accessTokenID,
		UserID: in.UserID,
		Iat:    iat.UnixMilli(),
		Exp:    iat.Add(s.cfg.AccessToken.TTL).UnixMilli(),
	}
	logger.Info(ctx, "access token claims: %v", accessTokenClaims.toString())

	// define claims for access token
	refreshTokenID := uuid.New().String()
	if in.Opts.RefreshTokenID != "" {
		refreshTokenID = in.Opts.RefreshTokenID
	}
	refreshTokenClaims := Claims{
		ID:     refreshTokenID,
		UserID: in.UserID,
		Iat:    iat.UnixMilli(),
		Exp:    iat.Add(s.cfg.RefreshToken.TTL).UnixMilli(),
	}
	logger.Info(ctx, "refresh token claims: %v", refreshTokenClaims.toString())

	// create access token
	authToken.AccessToken, err = s.tokenMaker.Generate(ctx, accessTokenClaims, s.cfg.AccessToken.Secret)
	if err != nil {
		logger.Error(ctx, "error while creating access token cause %v", err)
		return
	}

	// create refresh token
	authToken.RefreshToken, err = s.tokenMaker.Generate(ctx, refreshTokenClaims, s.cfg.RefreshToken.Secret)
	if err != nil {
		logger.Error(ctx, "error while creating refresh token cause %v", err)
		return
	}

	// store access token
	err = s.authRepo.Insert(ctx, fmt.Sprintf("%s%s", s.cfg.AccessToken.Name, accessTokenClaims.UserID), accessTokenClaims, s.cfg.AccessToken.TTL)
	if err != nil {
		logger.Error(ctx, "error while storing access token cause %v", err)
		return
	}

	// store refresh token
	err = s.authRepo.Insert(ctx, fmt.Sprintf("%s%s", s.cfg.RefreshToken.Name, accessTokenClaims.UserID), refreshTokenClaims, s.cfg.RefreshToken.TTL)
	if err != nil {
		logger.Error(ctx, "error while storing refresh token cause %v", err)
		return
	}

	logger.Info(ctx, "success creating token pair, data: %v", authToken.toString())

	return
}

// Validate: validate access token
func (s *service) Validate(ctx context.Context, accessToken string) (claims *Claims, err error) {
	// validate token
	claims, err = s.tokenMaker.Validate(ctx, accessToken, s.cfg.AccessToken.Secret)
	if err != nil {
		logger.Error(ctx, "error while validating token cause %v", err)
		return
	}
	logger.Info(ctx, "success validating token, data: %v", claims.toString())

	// get access token claims from db
	storedClaims, err := s.authRepo.Find(ctx, fmt.Sprintf("%s%s", s.cfg.AccessToken.Name, claims.UserID))
	if err != nil {
		logger.Error(ctx, "error while getting access token claims from db cause %v", err)
		err = ErrTokenExpired
		return
	}
	logger.Info(ctx, "success getting access token claims from db, data: %v", storedClaims.toString())

	// validate claims
	if storedClaims != *claims {
		logger.Error(ctx, "error while validating claims, claims mismatch")
		err = ErrTokenInvalid
		return
	}
	logger.Info(ctx, "success validating claims")

	return
}

// Refresh: regenerate access and refresh token after success validating refresh token
func (s *service) Refresh(ctx context.Context, in InputRefreshToken) (authToken Auth, err error) {
	// validate token
	claims, err := s.tokenMaker.Validate(ctx, in.Token, s.cfg.RefreshToken.Secret)
	if err != nil {
		logger.Error(ctx, "error while validating token cause %v", err)
		return
	}
	logger.Info(ctx, "success validating token, data: %v", claims.toString())

	// get refresh token claims
	storedClaims, err := s.authRepo.Find(ctx, fmt.Sprintf("%s%s", s.cfg.RefreshToken.Name, claims.UserID))
	if err != nil {
		logger.Error(ctx, "error while getting refresh token claims from db cause %v", err)
		err = ErrTokenExpired
		return
	}
	logger.Info(ctx, "success getting refresh token claims from db, data: %v", storedClaims.toString())

	// validate claims
	if storedClaims != *claims {
		logger.Error(ctx, "error while validating claims, claims mismatch")
		err = ErrTokenInvalid
		return
	}
	logger.Info(ctx, "success validating claims")

	// regenerate access and refresh token
	logger.Info(ctx, "generating new token...")
	return s.Generate(ctx, InputGenerateToken{
		UserID: claims.UserID,
		Opts:   in.Opts,
	})
}

// Revoke: revoke access and refresh token
func (s *service) Revoke(ctx context.Context, userID string) (err error) {
	// delete access token claims
	err = s.authRepo.Delete(ctx, fmt.Sprintf("%s%s", s.cfg.AccessToken.Name, userID))
	if err != nil {
		logger.Error(ctx, "error while deleting access token from db cause %v", err)
		return
	}

	// delete refresh token claims
	err = s.authRepo.Delete(ctx, fmt.Sprintf("%s%s", s.cfg.RefreshToken.Name, userID))
	if err != nil {
		logger.Error(ctx, "error while deleting access token from db cause %v", err)
		return
	}

	return
}
