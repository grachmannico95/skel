package user

import (
	"encoding/json"
	"fmt"
	"time"
)

var (
	ErrValidation          = fmt.Errorf("validation failed")
	ErrNotFound            = fmt.Errorf("not found")
	ErrUsernameAlreadyUsed = fmt.Errorf("username already used")
	ErrPasswordNotMatch    = fmt.Errorf("password not match")
)

// User: as user entity
type User struct {
	ID        string `validate:"required"`
	Username  string
	Name      string
	Password  string
	CreatedAt time.Time
	UpdatedAt time.Time
	Deleted   int8
}

func (u User) MarshalJSON() (b []byte, err error) {
	type data struct {
		ID        string `validate:"required"`
		Username  string
		Name      string
		Password  string
		CreatedAt time.Time
		UpdatedAt time.Time
		Deleted   int8
	}

	d := data{
		ID:        u.ID,
		Username:  u.Username,
		Name:      u.Name,
		Password:  "xxx",
		CreatedAt: u.CreatedAt,
		UpdatedAt: u.UpdatedAt,
		Deleted:   u.Deleted,
	}

	return json.Marshal(d)
}

func (u *User) UnmarshalJSON(data []byte) (err error) {
	return json.Unmarshal(data, u)
}

func (u User) toString() string {
	b, _ := u.MarshalJSON()
	return string(b)
}

// ***

// InputUserIdentifier: form to get user by user's identifier
type InputUserIdentifier struct {
	ID       string
	Username string
	Deleted  int
}

// InputUserCredential: form to get user by user's credential
type InputUserCredential struct {
	Username string `validate:"required"`
	Password string `validate:"required,min=8"`
}

// InputCreateUser: form to create user
type InputCreateUser struct {
	Username string `validate:"required"`
	Name     string `validate:"required"`
	Password string `validate:"required,min=8"`
}

// InputCreateUser: form to perform change user's username
type InputChangeUsername struct {
	ID        string `validate:"required"`
	Username  string `validate:"required"`
	UpdatedAt *time.Time
}

// InputChangeName: form to perform change user's name
type InputChangeName struct {
	ID        string `validate:"required"`
	Name      string `validate:"required"`
	UpdatedAt *time.Time
}

// InputChangePassword: form to perform change user's password
type InputChangePassword struct {
	ID          string `validate:"required"`
	OldPassword string `validate:"required,min=8"`
	NewPassword string `validate:"required,min=8"`
	UpdatedAt   *time.Time
}

// InputUserIdentifier: form to get user by user's identifier
type InputDeactivate struct {
	ID        string `validate:"required"`
	UpdatedAt *time.Time
}
