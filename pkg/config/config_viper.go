package config

import "github.com/spf13/viper"

type configViper struct {
	path       string
	fileName   string
	configType ConfigType
}

func NewConfigViper(path string, fileName string, configType ConfigType) Config {
	return &configViper{
		path:       path,
		fileName:   fileName,
		configType: configType,
	}
}

func (c *configViper) Read(config interface{}) (err error) {
	viper.SetConfigName(c.fileName)
	viper.SetConfigType(string(c.configType))
	viper.AddConfigPath(c.path)

	err = viper.ReadInConfig()
	if err != nil {
		return
	}

	err = viper.Unmarshal(&config)
	if err != nil {
		return
	}

	return
}
