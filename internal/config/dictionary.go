package config

import (
	"strings"

	"github.com/grachmannico95/skel/pkg/config"
)

type DictionaryKey map[string]string

type AppDictionary struct {
	Success             DictionaryKey `yaml:"success"`
	Err                 DictionaryKey `yaml:"err"`
	ErrBindRequest      DictionaryKey `yaml:"errBindRequest"`
	ErrValidation       DictionaryKey `yaml:"errValidation"`
	ErrDataNotFound     DictionaryKey `yaml:"errDataNotFound"`
	ErrDataAlreadyUsed  DictionaryKey `yaml:"errDataAlreadyUsed"`
	ErrDataDuplicate    DictionaryKey `yaml:"errDataDuplicate"`
	ErrPasswordNotMatch DictionaryKey `yaml:"errPasswordNotMatch"`
	ErrUnauthenticated  DictionaryKey `yaml:"errUnauthenticated"`
	ErrUnauthorized     DictionaryKey `yaml:"errUnauthorized"`
	ErrTokenInvalid     DictionaryKey `yaml:"errTokenInvalid"`
	ErrTokenExpired     DictionaryKey `yaml:"errTokenExpired"`
}

func NewDictionary(path string) (appDictionary AppDictionary) {
	dict := config.NewConfigViper(path, "dictionary", config.ConfigTypeYaml)
	dict.Read(&appDictionary)
	return
}

func (l DictionaryKey) GetLang(language string) string {
	language = strings.ToLower(language)
	if l[language] == "" {
		return l["en"]
	}
	return l[language]
}
