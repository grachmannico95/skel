package validator_test

import (
	"testing"

	"github.com/go-playground/assert/v2"
	"github.com/grachmannico95/skel/pkg/validator"
)

func TestValidator(t *testing.T) {
	type User struct {
		ID string `validate:"required"`
	}

	t.Run("success", func(t *testing.T) {
		// arrange
		u := User{ID: "1"}

		// action
		err := validator.ValidateStruct(u)

		// assert
		assert.Equal(t, err, nil)
	})

	t.Run("error validation", func(t *testing.T) {
		// arrange
		u := User{}

		// action
		err := validator.ValidateStruct(u)

		// assert
		assert.NotEqual(t, err, nil)
	})
}
