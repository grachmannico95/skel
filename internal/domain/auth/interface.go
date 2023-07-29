package auth

import (
	"context"
	"time"
)

type (
	//go:generate mockery --dir internal/domain/auth --inpackage --name AuthRepo --structname AuthRepoMock --outpkg=auth --output=internal/domain/auth --filename=repo_mock.go
	AuthRepo interface {
		Find(ctx context.Context, key string) (claims Claims, err error)
		Insert(ctx context.Context, key string, claims Claims, duration time.Duration) (err error)
		Delete(ctx context.Context, key string) (err error)
	}

	//go:generate mockery --dir internal/domain/auth --inpackage --name TokenMaker --structname TokenMakerMock --outpkg=auth --output=internal/domain/auth --filename=token_maker_mock.go
	TokenMaker interface {
		Generate(ctx context.Context, claims Claims, secret string) (token string, err error)
		Validate(ctx context.Context, token string, secret string) (claims *Claims, err error)
	}

	AuthService interface {
		Generate(ctx context.Context, in InputGenerateToken) (authToken Auth, err error)
		Validate(ctx context.Context, accessToken string) (claims *Claims, err error)
		Refresh(ctx context.Context, in InputRefreshToken) (authToken Auth, err error)
		Revoke(ctx context.Context, userID string) (err error)
	}
)
