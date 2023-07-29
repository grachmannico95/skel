package auth

import (
	"encoding/json"
	"time"
)

// Auth: as auth entity
type Auth struct {
	AccessToken  string
	RefreshToken string
}

func (a Auth) MarshalJSON() (b []byte, err error) {
	type data struct {
		AccessToken  string
		RefreshToken string
	}

	d := data(a)

	return json.Marshal(d)
}

func (a *Auth) UnmarshalJSON(data []byte) (err error) {
	return json.Unmarshal(data, a)
}

func (a Auth) toString() string {
	b, _ := a.MarshalJSON()
	return string(b)
}

// ***

type OptsToken struct {
	AccessTokenID  string
	RefreshTokenID string
	Time           time.Time
}

// InputGenerateToken: form to generate token
type InputGenerateToken struct {
	UserID string `validate:"required"`
	Opts   OptsToken
	// AccessTokenID  string
	// RefreshTokenID string
	// Time           time.Time
}

// InputGenerateToken: form to generate token
type InputRefreshToken struct {
	Token string `validate:"required"`
	Opts  OptsToken
}
