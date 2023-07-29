package validator

type validator interface {
	validateStruct(i interface{}) (err error)
}

// ***

type validatorInstance struct {
	engine validator
}

var v validatorInstance

func validate() *validatorInstance {
	if v.engine == nil {
		v.engine = newValidatorGoPlayground() // you can change whatever validator implementation
	}

	return &v
}

// ***

func ValidateStruct(i interface{}) (err error) {
	return validate().engine.validateStruct(i)
}
