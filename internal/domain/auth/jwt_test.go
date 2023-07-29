package auth_test

import (
	"context"
	"testing"
	"time"

	"github.com/go-playground/assert/v2"
	"github.com/golang-jwt/jwt"
	"github.com/grachmannico95/skel/internal/domain/auth"
)

func TestGenerate(t *testing.T) {
	var cfgGenerate = auth.Config{
		AccessToken: auth.AccessTokenConfig{
			Secret: "secret",
		},
	}

	t.Run("generate success", func(t *testing.T) {
		// arrange
		ctx := context.Background()
		tokenMaker := auth.NewJwtMaker(jwt.SigningMethodHS256)

		// act
		accessToken, err := tokenMaker.Generate(ctx, auth.Claims{}, cfgGenerate.AccessToken.Secret)

		// assert
		assert.Equal(t, err, nil)
		assert.NotEqual(t, accessToken, "")
	})

	t.Run("generate failed", func(t *testing.T) {
		// arrange
		ctx := context.Background()
		tokenMaker := auth.NewJwtMaker(jwt.SigningMethodNone)

		// act
		accessToken, err := tokenMaker.Generate(ctx, auth.Claims{}, cfgGenerate.AccessToken.Secret)

		// assert
		assert.NotEqual(t, err, nil)
		assert.Equal(t, accessToken, "")
	})
}

func TestValidate(t *testing.T) {
	var cfgValidate = auth.Config{
		AccessToken: auth.AccessTokenConfig{
			Secret: "secret",
		},
	}

	t.Run("validate success", func(t *testing.T) {
		// arrange
		ctx := context.Background()
		claims := auth.Claims{
			ID:     "1",
			UserID: "1",
			Iat:    time.Now().UnixMilli(),
			Exp:    time.Now().Add(1 * time.Minute).UnixMilli(),
		}
		tokenMaker := auth.NewJwtMaker(jwt.SigningMethodHS256)

		// act
		accessToken, _ := tokenMaker.Generate(ctx, claims, cfgValidate.AccessToken.Secret)
		resClaims, err := tokenMaker.Validate(ctx, accessToken, cfgValidate.AccessToken.Secret)

		// assert
		assert.Equal(t, err, nil)
		assert.Equal(t, resClaims, claims)
	})

	t.Run("token invalid: secret not match", func(t *testing.T) {
		t.Run("validate success", func(t *testing.T) {
			// arrange
			ctx := context.Background()
			claims := auth.Claims{
				ID:     "1",
				UserID: "1",
				Iat:    time.Now().UnixMilli(),
				Exp:    time.Now().Add(1 * time.Minute).UnixMilli(),
			}
			tokenMaker := auth.NewJwtMaker(jwt.SigningMethodHS256)

			// act
			accessToken, _ := tokenMaker.Generate(ctx, claims, cfgValidate.AccessToken.Secret)
			resClaims, err := tokenMaker.Validate(ctx, accessToken, "false secret")

			// assert
			assert.Equal(t, err, auth.ErrTokenInvalid)
			assert.Equal(t, resClaims, nil)
		})
	})

	t.Run("token invalid: signing method not match", func(t *testing.T) {
		t.Run("validate success", func(t *testing.T) {
			// arrange
			ctx := context.Background()
			tokenMaker := auth.NewJwtMaker(jwt.SigningMethodHS256)

			// act
			accessToken := "eyJhbGciOiJSUzUxMiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0.jYW04zLDHfR1v7xdrW3lCGZrMIsVe0vWCfVkN2DRns2c3MN-mcp_-RE6TN9umSBYoNV-mnb31wFf8iun3fB6aDS6m_OXAiURVEKrPFNGlR38JSHUtsFzqTOj-wFrJZN4RwvZnNGSMvK3wzzUriZqmiNLsG8lktlEn6KA4kYVaM61_NpmPHWAjGExWv7cjHYupcjMSmR8uMTwN5UuAwgW6FRstCJEfoxwb0WKiyoaSlDuIiHZJ0cyGhhEmmAPiCwtPAwGeaL1yZMcp0p82cpTQ5Qb-7CtRov3N4DcOHgWYk6LomPR5j5cCkePAz87duqyzSMpCB0mCOuE3CU2VMtGeQ"
			resClaims, err := tokenMaker.Validate(ctx, accessToken, "false secret")

			// assert
			assert.Equal(t, err, auth.ErrTokenInvalid)
			assert.Equal(t, resClaims, nil)
		})
	})

	t.Run("token expired", func(t *testing.T) {
		t.Run("validate success", func(t *testing.T) {
			// arrange
			ctx := context.Background()
			claims := auth.Claims{
				ID:     "1",
				UserID: "1",
				Iat:    time.Now().UnixMilli(),
				Exp:    time.Now().UnixMilli(),
			}
			tokenMaker := auth.NewJwtMaker(jwt.SigningMethodHS256)

			// act
			accessToken, _ := tokenMaker.Generate(ctx, claims, cfgValidate.AccessToken.Secret)
			resClaims, err := tokenMaker.Validate(ctx, accessToken, cfgValidate.AccessToken.Secret)

			// assert
			assert.Equal(t, err, auth.ErrTokenExpired)
			assert.Equal(t, resClaims, nil)
		})
	})
}
