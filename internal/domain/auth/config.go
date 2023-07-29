package auth

import "time"

// Config: auth service configuration
type Config struct {
	AccessToken  AccessTokenConfig  `validate:"required"`
	RefreshToken RefreshTokenConfig `validate:"required"`
}

// AccessTokenConfig: access token configuration
type AccessTokenConfig struct {
	Name   string        `validate:"required"`
	TTL    time.Duration `validate:"required"`
	Secret string        `validate:"required"`
}

// RefreshTokenConfig: refresh token configuration
type RefreshTokenConfig struct {
	Name   string        `validate:"required"`
	TTL    time.Duration `validate:"required"`
	Secret string        `validate:"required"`
}
