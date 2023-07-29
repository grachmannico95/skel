package auth

import (
	"encoding/json"
	"fmt"
	"time"
)

var (
	ErrValidation   = fmt.Errorf("validation failed")
	ErrTokenInvalid = fmt.Errorf("token invalid")
	ErrTokenExpired = fmt.Errorf("token expired")
)

// Claims: as claim entity, used as token validation
type Claims struct {
	ID     string `json:"id"`
	UserID string `json:"user_id"`
	Iat    int64  `json:"iat"`
	Exp    int64  `json:"exp"`
}

func (c Claims) MarshalJSON() (b []byte, err error) {
	type data struct {
		ID     string `json:"id"`
		UserID string `json:"user_id"`
		Iat    int64  `json:"iat"`
		Exp    int64  `json:"exp"`
	}

	d := data(c)

	return json.Marshal(d)
}

func (c Claims) toString() string {
	b, _ := c.MarshalJSON()
	return string(b)
}

// Valid: implementation of go jwt claim validation
func (c *Claims) Valid() error {
	if time.Now().After(time.UnixMilli(c.Exp)) {
		return ErrTokenExpired
	}
	return nil
}
