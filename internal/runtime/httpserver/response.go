package httpserver

import "fmt"

type responseStructure struct {
	Status  bool        `json:"status"`
	Message string      `json:"message"`
	Data    interface{} `json:"data"`
}

type status bool

var (
	Success status = true
	Failed  status = false
)

// ***

var Resp map[status]responseStructure = map[status]responseStructure{
	Success: {Status: true, Data: map[string]interface{}{}},
	Failed:  {Status: false, Data: map[string]interface{}{}},
}

func (r responseStructure) ClearMessage() responseStructure {
	r.Message = ""
	return r
}

func (r responseStructure) AddMessage(message string) responseStructure {
	if r.Message != "" {
		message = fmt.Sprintf("%s %s", r.Message, message)
	}
	r.Message = message
	return r
}

func (r responseStructure) AddData(data interface{}) responseStructure {
	r.Data = data
	return r
}
