package config

import (
	"time"

	"github.com/grachmannico95/skel/pkg/config"
)

type AppConfig struct {
	App       App       `yaml:"app"`
	Db        Db        `yaml:"db"`
	Log       Log       `yaml:"log"`
	Constants Constants `yaml:"constants"`
}

type App struct {
	Name string `yaml:"name"`
	Ver  string `yaml:"ver"`
	Port string `yaml:"port"`
	Env  string `yaml:"env"`
}

type Connection struct {
	MaxIdle     int           `yaml:"maxIdle"`
	MaxOpen     int           `yaml:"maxOpen"`
	MaxLifetime time.Duration `yaml:"maxLifetime"`
}

type Mysql struct {
	Username   string     `yaml:"username"`
	Password   string     `yaml:"password"`
	Host       string     `yaml:"host"`
	Port       string     `yaml:"port"`
	Name       string     `yaml:"name"`
	Connection Connection `yaml:"connection"`
}

type Redis struct {
	Host     string `yaml:"host"`
	Port     string `yaml:"port"`
	Password string `yaml:"password"`
	DbNum    int    `yaml:"dbNum"`
}

type Db struct {
	Mysql Mysql `yaml:"mysql"`
	Redis Redis `yaml:"redis"`
}

type Log struct {
	SeverityLevel int `yaml:"severityLevel"`
}

type Constants struct {
	AccessTokenName    string        `yaml:"accessTokenName"`
	AccessTokenTTL     time.Duration `yaml:"accessTokenTTL"`
	AccessTokenSecret  string        `yaml:"accessTokenSecret"`
	RefreshTokenName   string        `yaml:"refreshTokenName"`
	RefreshTokenTTL    time.Duration `yaml:"refreshTokenTTL"`
	RefreshTokenSecret string        `yaml:"refreshTokenSecret"`
}

// ***

func NewAppConfig(path string, name string) (appConfig AppConfig) {
	cfg := config.NewConfigViper(path, name, config.ConfigTypeYaml)
	cfg.Read(&appConfig)
	return
}
