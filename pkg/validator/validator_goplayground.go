package validator

import govalidator "github.com/go-playground/validator/v10"

type validatorGoPlayground struct {
	validate *govalidator.Validate
}

func newValidatorGoPlayground() *validatorGoPlayground {
	return &validatorGoPlayground{
		validate: govalidator.New(),
	}
}

func (v *validatorGoPlayground) validateStruct(i interface{}) (err error) {
	return v.validate.Struct(i)
}
