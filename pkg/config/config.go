package config

type ConfigType string

var (
	ConfigTypeYaml ConfigType = "yaml"
	ConfigTypeJson ConfigType = "json"
	ConfigTypeEnv  ConfigType = "env"
)

type Config interface {
	Read(config interface{}) (err error)
}
