package auth_test

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/go-playground/assert/v2"
	"github.com/golang-jwt/jwt"
	"github.com/grachmannico95/skel/internal/domain/auth"
)

var cfg = auth.Config{
	AccessToken: auth.AccessTokenConfig{
		TTL:    1 * time.Minute,
		Name:   "access:",
		Secret: "secret",
	},
	RefreshToken: auth.RefreshTokenConfig{
		TTL:    1 * time.Minute,
		Name:   "refresh:",
		Secret: "secret",
	},
}

func TestNewInstance(t *testing.T) {
	// prepare mock
	repoMock := func() auth.AuthRepo {
		mock := new(auth.AuthRepoMock)
		return mock
	}

	// prepare test cases
	testCases := []struct {
		name    string
		cfg     auth.Config
		wantErr error
	}{
		{
			name: "success",
			cfg:  cfg,
		},
		{
			name:    "validation failed",
			cfg:     auth.Config{},
			wantErr: auth.ErrValidation,
		},
	}

	// perform unit test
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// arrange
			tokenMaker := auth.NewJwtMaker(jwt.SigningMethodHS256)
			_, err := auth.NewService(repoMock(), tokenMaker, tc.cfg)

			// act

			// assert
			assert.Equal(t, tc.wantErr, err)
		})
	}
}

func TestGenerateToken(t *testing.T) {
	// prepare args
	type argsInsert struct {
		ctx    context.Context
		claims auth.Claims
		err    error
	}
	type argsTokenMaker struct {
		ctx    context.Context
		claims auth.Claims
		secret string
		token  string
		err    error
	}
	type mockArgs struct {
		insertAccessToken      argsInsert
		insertRefreshToken     argsInsert
		tokenMakerAccessToken  argsTokenMaker
		tokenMakerRefreshToken argsTokenMaker
	}

	// prepare mock
	repoMock := func(args mockArgs) auth.AuthRepo {
		mock := new(auth.AuthRepoMock)
		mock.On("Insert", args.insertAccessToken.ctx, fmt.Sprintf("%s%s", cfg.AccessToken.Name, "1"), args.insertAccessToken.claims, cfg.AccessToken.TTL).Return(args.insertAccessToken.err).Once()
		mock.On("Insert", args.insertRefreshToken.ctx, fmt.Sprintf("%s%s", cfg.RefreshToken.Name, "1"), args.insertRefreshToken.claims, cfg.RefreshToken.TTL).Return(args.insertRefreshToken.err).Once()
		return mock
	}
	mockJwt := func(args mockArgs) auth.TokenMaker {
		mock := new(auth.TokenMakerMock)
		mock.On("Generate", args.tokenMakerAccessToken.ctx, args.tokenMakerAccessToken.claims, args.tokenMakerAccessToken.secret).Return(args.tokenMakerAccessToken.token, args.tokenMakerAccessToken.err).Once()
		mock.On("Generate", args.tokenMakerRefreshToken.ctx, args.tokenMakerRefreshToken.claims, args.tokenMakerRefreshToken.secret).Return(args.tokenMakerRefreshToken.token, args.tokenMakerRefreshToken.err).Once()
		return mock
	}

	// prepare value
	timeNow := time.Now()
	value := struct {
		ctx    context.Context
		claims auth.Claims
		token  string
		err    error
	}{
		ctx: context.Background(),
		claims: auth.Claims{
			ID:     "1",
			UserID: "1",
			Iat:    timeNow.UnixMilli(),
			Exp:    timeNow.Add(1 * time.Minute).UnixMilli(),
		},
		token: "token",
		err:   errors.New("err"),
	}

	// prepare test cases
	testCases := []struct {
		name    string
		args    mockArgs
		want    auth.Auth
		wantErr error
	}{
		{
			name: "generate success",
			args: mockArgs{
				insertAccessToken: argsInsert{
					ctx:    value.ctx,
					claims: value.claims,
				},
				insertRefreshToken: argsInsert{
					ctx:    value.ctx,
					claims: value.claims,
				},
				tokenMakerAccessToken: argsTokenMaker{
					ctx:    value.ctx,
					claims: value.claims,
					secret: cfg.AccessToken.Secret,
					token:  value.token,
				},
				tokenMakerRefreshToken: argsTokenMaker{
					ctx:    value.ctx,
					claims: value.claims,
					secret: cfg.RefreshToken.Secret,
					token:  value.token,
				},
			},
			want: auth.Auth{
				AccessToken:  value.token,
				RefreshToken: value.token,
			},
		},
		{
			name: "validation failed",
			args: mockArgs{
				insertAccessToken:      argsInsert{},
				insertRefreshToken:     argsInsert{},
				tokenMakerAccessToken:  argsTokenMaker{},
				tokenMakerRefreshToken: argsTokenMaker{},
			},
			wantErr: auth.ErrValidation,
		},
		{
			name: "error while generating access token",
			args: mockArgs{
				insertAccessToken: argsInsert{
					ctx:    value.ctx,
					claims: value.claims,
				},
				insertRefreshToken: argsInsert{
					ctx:    value.ctx,
					claims: value.claims,
				},
				tokenMakerAccessToken: argsTokenMaker{
					ctx:    value.ctx,
					claims: value.claims,
					secret: cfg.AccessToken.Secret,
					token:  "",
					err:    value.err,
				},
				tokenMakerRefreshToken: argsTokenMaker{
					ctx:    value.ctx,
					claims: value.claims,
					secret: cfg.AccessToken.Secret,
					token:  value.token,
				},
			},
			want:    auth.Auth{},
			wantErr: value.err,
		},
		{
			name: "error while generating refresh token",
			args: mockArgs{
				insertAccessToken: argsInsert{
					ctx:    value.ctx,
					claims: value.claims,
				},
				insertRefreshToken: argsInsert{
					ctx:    value.ctx,
					claims: value.claims,
				},
				tokenMakerAccessToken: argsTokenMaker{
					ctx:    value.ctx,
					claims: value.claims,
					secret: cfg.AccessToken.Secret,
					token:  value.token,
				},
				tokenMakerRefreshToken: argsTokenMaker{
					ctx:    value.ctx,
					claims: value.claims,
					secret: cfg.AccessToken.Secret,
					token:  "",
					err:    value.err,
				},
			},
			want: auth.Auth{
				AccessToken: value.token,
			},
			wantErr: value.err,
		},
		{
			name: "error while storing access token",
			args: mockArgs{
				insertAccessToken: argsInsert{
					ctx:    value.ctx,
					claims: value.claims,
					err:    value.err,
				},
				insertRefreshToken: argsInsert{
					ctx:    value.ctx,
					claims: value.claims,
				},
				tokenMakerAccessToken: argsTokenMaker{
					ctx:    value.ctx,
					claims: value.claims,
					secret: cfg.AccessToken.Secret,
					token:  value.token,
				},
				tokenMakerRefreshToken: argsTokenMaker{
					ctx:    value.ctx,
					claims: value.claims,
					secret: cfg.RefreshToken.Secret,
					token:  value.token,
				},
			},
			want: auth.Auth{
				AccessToken:  value.token,
				RefreshToken: value.token,
			},
			wantErr: value.err,
		},
		{
			name: "error while storing refresh token",
			args: mockArgs{
				insertAccessToken: argsInsert{
					ctx:    value.ctx,
					claims: value.claims,
				},
				insertRefreshToken: argsInsert{
					ctx:    value.ctx,
					claims: value.claims,
					err:    value.err,
				},
				tokenMakerAccessToken: argsTokenMaker{
					ctx:    value.ctx,
					claims: value.claims,
					secret: cfg.AccessToken.Secret,
					token:  value.token,
				},
				tokenMakerRefreshToken: argsTokenMaker{
					ctx:    value.ctx,
					claims: value.claims,
					secret: cfg.RefreshToken.Secret,
					token:  value.token,
				},
			},
			want: auth.Auth{
				AccessToken:  value.token,
				RefreshToken: value.token,
			},
			wantErr: value.err,
		},
	}

	// perform unit test
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// arrange
			svc, _ := auth.NewService(repoMock(tc.args), mockJwt(tc.args), cfg)

			// act
			got, err := svc.Generate(value.ctx, auth.InputGenerateToken{
				UserID: tc.args.insertAccessToken.claims.UserID,
				Opts: auth.OptsToken{
					AccessTokenID:  tc.args.insertAccessToken.claims.ID,
					RefreshTokenID: tc.args.insertRefreshToken.claims.ID,
					Time:           timeNow,
				},
			})

			// assert
			assert.Equal(t, tc.want, got)
			assert.Equal(t, tc.wantErr, err)
		})
	}
}

func TestValidateToken(t *testing.T) {
	// prepare args
	type argsFind struct {
		ctx    context.Context
		claims auth.Claims
		err    error
	}
	type argsTokenMaker struct {
		ctx    context.Context
		token  string
		secret string
		claims *auth.Claims
		err    error
	}
	type mockArgs struct {
		find       argsFind
		tokenMaker argsTokenMaker
	}

	// prepare mock
	repoMock := func(args mockArgs) auth.AuthRepo {
		mock := new(auth.AuthRepoMock)
		mock.On("Find", args.find.ctx, fmt.Sprintf("%s%s", cfg.AccessToken.Name, "1")).Return(args.find.claims, args.find.err).Once()
		return mock
	}
	mockJwt := func(args mockArgs) auth.TokenMaker {
		mock := new(auth.TokenMakerMock)
		mock.On("Validate", args.tokenMaker.ctx, args.tokenMaker.token, args.tokenMaker.secret).Return(args.tokenMaker.claims, args.tokenMaker.err).Once()
		return mock
	}

	// prepare value
	timeNow := time.Now()
	value := struct {
		ctx    context.Context
		token  string
		claims auth.Claims
		err    error
	}{
		ctx:   context.Background(),
		token: "",
		claims: auth.Claims{
			ID:     "1",
			UserID: "1",
			Iat:    timeNow.UnixMilli(),
			Exp:    timeNow.Add(1 * time.Minute).UnixMilli(),
		},
		err: errors.New("err"),
	}

	// prepare test cases
	testCases := []struct {
		name    string
		args    mockArgs
		want    *auth.Claims
		wantErr error
	}{
		{
			name: "validate success",
			args: mockArgs{
				find: argsFind{
					ctx:    value.ctx,
					claims: value.claims,
				},
				tokenMaker: argsTokenMaker{
					ctx:    value.ctx,
					token:  value.token,
					secret: cfg.AccessToken.Secret,
					claims: &value.claims,
				},
			},
			want: &value.claims,
		},
		{
			name: "token invalid",
			args: mockArgs{
				find: argsFind{
					ctx:    value.ctx,
					claims: value.claims,
				},
				tokenMaker: argsTokenMaker{
					ctx:    value.ctx,
					token:  value.token,
					secret: cfg.AccessToken.Secret,
					claims: &value.claims,
					err:    auth.ErrTokenInvalid,
				},
			},
			want:    &value.claims,
			wantErr: auth.ErrTokenInvalid,
		},
		{
			name: "error while getting claims data",
			args: mockArgs{
				find: argsFind{
					ctx:    value.ctx,
					claims: auth.Claims{},
					err:    auth.ErrTokenExpired,
				},
				tokenMaker: argsTokenMaker{
					ctx:    value.ctx,
					token:  value.token,
					secret: cfg.AccessToken.Secret,
					claims: &value.claims,
				},
			},
			want:    &value.claims,
			wantErr: auth.ErrTokenExpired,
		},
		{
			name: "invalid claims",
			args: mockArgs{
				find: argsFind{
					ctx:    value.ctx,
					claims: auth.Claims{},
				},
				tokenMaker: argsTokenMaker{
					ctx:    value.ctx,
					token:  value.token,
					secret: cfg.AccessToken.Secret,
					claims: &value.claims,
				},
			},
			want:    &value.claims,
			wantErr: auth.ErrTokenInvalid,
		},
	}

	// perform unit test
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// arrange
			svc, _ := auth.NewService(repoMock(tc.args), mockJwt(tc.args), cfg)

			// act
			got, err := svc.Validate(value.ctx, tc.args.tokenMaker.token)

			// assert
			assert.Equal(t, tc.want, got)
			assert.Equal(t, tc.wantErr, err)
		})
	}
}

func TestRefreshToken(t *testing.T) {
	// prepare args
	type argsFind struct {
		ctx    context.Context
		claims auth.Claims
		err    error
	}
	type argsInsert struct {
		ctx    context.Context
		claims auth.Claims
		err    error
	}
	type argsTokenMakerValidate struct {
		ctx    context.Context
		token  string
		secret string
		claims *auth.Claims
		err    error
	}
	type argsTokenMakerGenerate struct {
		ctx    context.Context
		claims auth.Claims
		secret string
		token  string
		err    error
	}
	type mockArgs struct {
		tokenMakerValidate argsTokenMakerValidate
		find               argsFind

		tokenMakerAccessToken  argsTokenMakerGenerate
		tokenMakerRefreshToken argsTokenMakerGenerate
		insertAccessToken      argsInsert
		insertRefreshToken     argsInsert
	}

	// prepare mock
	repoMock := func(args mockArgs) auth.AuthRepo {
		mock := new(auth.AuthRepoMock)
		mock.On("Find", args.find.ctx, fmt.Sprintf("%s%s", cfg.RefreshToken.Name, "1")).Return(args.find.claims, args.find.err).Once()
		mock.On("Insert", args.insertAccessToken.ctx, fmt.Sprintf("%s%s", cfg.AccessToken.Name, "1"), args.insertAccessToken.claims, cfg.AccessToken.TTL).Return(args.insertAccessToken.err).Once()
		mock.On("Insert", args.insertRefreshToken.ctx, fmt.Sprintf("%s%s", cfg.RefreshToken.Name, "1"), args.insertRefreshToken.claims, cfg.RefreshToken.TTL).Return(args.insertRefreshToken.err).Once()
		return mock
	}
	mockJwt := func(args mockArgs) auth.TokenMaker {
		mock := new(auth.TokenMakerMock)
		mock.On("Validate", args.tokenMakerValidate.ctx, args.tokenMakerValidate.token, args.tokenMakerValidate.secret).Return(args.tokenMakerValidate.claims, args.tokenMakerValidate.err).Once()
		mock.On("Generate", args.tokenMakerAccessToken.ctx, args.tokenMakerAccessToken.claims, args.tokenMakerAccessToken.secret).Return(args.tokenMakerAccessToken.token, args.tokenMakerAccessToken.err).Once()
		mock.On("Generate", args.tokenMakerRefreshToken.ctx, args.tokenMakerRefreshToken.claims, args.tokenMakerRefreshToken.secret).Return(args.tokenMakerRefreshToken.token, args.tokenMakerRefreshToken.err).Once()
		return mock
	}

	// prepare value
	timeNow := time.Now()
	value := struct {
		ctx    context.Context
		claims auth.Claims
		token  string
		err    error
	}{
		ctx: context.Background(),
		claims: auth.Claims{
			ID:     "1",
			UserID: "1",
			Iat:    timeNow.UnixMilli(),
			Exp:    timeNow.Add(1 * time.Minute).UnixMilli(),
		},
		token: "token",
		err:   errors.New("err"),
	}

	// prepare test cases
	testCases := []struct {
		name    string
		args    mockArgs
		want    auth.Auth
		wantErr error
	}{
		{
			name: "refresh success",
			args: mockArgs{
				tokenMakerValidate: argsTokenMakerValidate{
					ctx:    value.ctx,
					token:  value.token,
					secret: cfg.RefreshToken.Secret,
					claims: &value.claims,
				},
				find: argsFind{
					ctx:    value.ctx,
					claims: value.claims,
				},
				tokenMakerAccessToken: argsTokenMakerGenerate{
					ctx:    value.ctx,
					claims: value.claims,
					secret: cfg.AccessToken.Secret,
					token:  value.token,
				},
				tokenMakerRefreshToken: argsTokenMakerGenerate{
					ctx:    value.ctx,
					claims: value.claims,
					secret: cfg.RefreshToken.Secret,
					token:  value.token,
				},
				insertAccessToken: argsInsert{
					ctx:    value.ctx,
					claims: value.claims,
				},
				insertRefreshToken: argsInsert{
					ctx:    value.ctx,
					claims: value.claims,
				},
			},
			want: auth.Auth{
				AccessToken:  value.token,
				RefreshToken: value.token,
			},
		},
		{
			name: "error while validate refresh token",
			args: mockArgs{
				tokenMakerValidate: argsTokenMakerValidate{
					ctx:    value.ctx,
					token:  value.token,
					secret: cfg.AccessToken.Secret,
					claims: &value.claims,
					err:    auth.ErrTokenExpired,
				},
				find: argsFind{
					ctx:    value.ctx,
					claims: value.claims,
				},
				tokenMakerAccessToken:  argsTokenMakerGenerate{},
				tokenMakerRefreshToken: argsTokenMakerGenerate{},
				insertAccessToken:      argsInsert{},
				insertRefreshToken:     argsInsert{},
			},
			want:    auth.Auth{},
			wantErr: auth.ErrTokenExpired,
		},
		{
			name: "refresh success",
			args: mockArgs{
				tokenMakerValidate: argsTokenMakerValidate{
					ctx:    value.ctx,
					token:  value.token,
					secret: cfg.RefreshToken.Secret,
					claims: &value.claims,
				},
				find: argsFind{
					ctx:    value.ctx,
					claims: value.claims,
					err:    value.err,
				},
				tokenMakerAccessToken:  argsTokenMakerGenerate{},
				tokenMakerRefreshToken: argsTokenMakerGenerate{},
				insertAccessToken:      argsInsert{},
				insertRefreshToken:     argsInsert{},
			},
			want:    auth.Auth{},
			wantErr: auth.ErrTokenExpired,
		},
		{
			name: "invalid claims",
			args: mockArgs{
				tokenMakerValidate: argsTokenMakerValidate{
					ctx:    value.ctx,
					token:  value.token,
					secret: cfg.RefreshToken.Secret,
					claims: &value.claims,
				},
				find: argsFind{
					ctx:    value.ctx,
					claims: auth.Claims{},
				},
				tokenMakerAccessToken:  argsTokenMakerGenerate{},
				tokenMakerRefreshToken: argsTokenMakerGenerate{},
				insertAccessToken:      argsInsert{},
				insertRefreshToken:     argsInsert{},
			},
			want:    auth.Auth{},
			wantErr: auth.ErrTokenInvalid,
		},
	}

	// perform unit test
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// arrange
			svc, _ := auth.NewService(repoMock(tc.args), mockJwt(tc.args), cfg)

			// act
			got, err := svc.Refresh(value.ctx, auth.InputRefreshToken{
				Token: tc.args.tokenMakerValidate.token,
				Opts: auth.OptsToken{
					AccessTokenID:  tc.args.insertAccessToken.claims.ID,
					RefreshTokenID: tc.args.insertRefreshToken.claims.ID,
					Time:           timeNow,
				},
			})

			// assert
			assert.Equal(t, tc.want, got)
			assert.Equal(t, tc.wantErr, err)
		})
	}
}

func TestRevokeToken(t *testing.T) {
	// prepare args
	type argsDelete struct {
		ctx context.Context
		err error
	}
	type mockArgs struct {
		deleteAccessToken  argsDelete
		deleteRefreshToken argsDelete
	}

	// prepare mock
	repoMock := func(args mockArgs) auth.AuthRepo {
		mock := new(auth.AuthRepoMock)
		mock.On("Delete", args.deleteAccessToken.ctx, fmt.Sprintf("%s%s", cfg.AccessToken.Name, "1")).Return(args.deleteAccessToken.err).Once()
		mock.On("Delete", args.deleteRefreshToken.ctx, fmt.Sprintf("%s%s", cfg.RefreshToken.Name, "1")).Return(args.deleteRefreshToken.err).Once()
		return mock
	}

	// prepare value
	value := struct {
		ctx    context.Context
		userID string
		err    error
	}{
		ctx:    context.Background(),
		userID: "1",
		err:    errors.New("err"),
	}

	// prepare test cases
	testCases := []struct {
		name    string
		args    mockArgs
		wantErr error
	}{
		{
			name: "revoke success",
			args: mockArgs{
				deleteAccessToken: argsDelete{
					ctx: value.ctx,
				},
				deleteRefreshToken: argsDelete{
					ctx: value.ctx,
				},
			},
		},
		{
			name: "error while deleting access token",
			args: mockArgs{
				deleteAccessToken: argsDelete{
					ctx: value.ctx,
					err: value.err,
				},
				deleteRefreshToken: argsDelete{
					ctx: value.ctx,
				},
			},
			wantErr: value.err,
		},
		{
			name: "error while deleting refresh token",
			args: mockArgs{
				deleteAccessToken: argsDelete{
					ctx: value.ctx,
				},
				deleteRefreshToken: argsDelete{
					ctx: value.ctx,
					err: value.err,
				},
			},
			wantErr: value.err,
		},
	}

	// perform unit test
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// arrange
			svc, _ := auth.NewService(repoMock(tc.args), auth.NewJwtMaker(jwt.SigningMethodHS256), cfg)

			// act
			err := svc.Revoke(value.ctx, value.userID)

			// assert
			assert.Equal(t, tc.wantErr, err)
		})
	}
}
