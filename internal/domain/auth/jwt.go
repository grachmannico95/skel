package auth

import (
	"context"
	"errors"

	"github.com/golang-jwt/jwt"
	"github.com/grachmannico95/skel/pkg/logger"
)

type jwtMaker struct {
	method jwt.SigningMethod
}

func NewJwtMaker(method jwt.SigningMethod) TokenMaker {
	return &jwtMaker{
		method: method,
	}
}

func (t *jwtMaker) Generate(ctx context.Context, claims Claims, secret string) (token string, err error) {
	// create new claims
	jwtToken := jwt.NewWithClaims(t.method, &claims)

	// create jwt token string
	token, err = jwtToken.SignedString([]byte(secret))
	if err != nil {
		logger.Error(ctx, "error while creating jwt token cause %v", err)
		return
	}

	return
}

func (t *jwtMaker) Validate(ctx context.Context, token string, secret string) (claims *Claims, err error) {
	keyFunc := func(token *jwt.Token) (interface{}, error) {
		_, ok := token.Method.(*jwt.SigningMethodHMAC)
		if !ok {
			return nil, ErrTokenInvalid
		}
		return []byte(secret), nil
	}

	// validate jwt token
	jwtMaker, err := jwt.ParseWithClaims(token, &Claims{}, keyFunc)
	if err != nil {
		verr, ok := err.(*jwt.ValidationError)
		if ok && errors.Is(verr.Inner, ErrTokenExpired) {
			logger.Error(ctx, "error while validating jwt token cause %v", ErrTokenExpired)
			return nil, ErrTokenExpired
		}
		logger.Error(ctx, "error while validating jwt token cause %v", verr)
		return nil, ErrTokenInvalid
	}

	// parse jwt claims
	claims = jwtMaker.Claims.(*Claims)

	return
}
