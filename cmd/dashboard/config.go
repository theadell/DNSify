package main

import (
	"log/slog"
	"strings"
	"time"

	"github.com/spf13/viper"
	"github.com/theadell/dnsify/internal/dnsservice"
)

type Config struct {
	DNSClientConfig    dnsservice.DNSConfig `mapstructure:"dns"`
	HTTPServerConfig   HTTPServerConfig     `mapstructure:"httpServer"`
	OAuth2ClientConfig OAuth2ClientConfig   `mapstructure:"oauth2Client"`
}

type HTTPServerConfig struct {
	Host         string `mapstructure:"host"`
	Port         uint   `mapstructure:"port"`
	SecureCookie bool   `mapstructure:"secureCookie"`
	pushInterval time.Duration
}

type OAuth2ClientConfig struct {
	ClientID     string `mapstructure:"clientID"`
	ClientSecret string `mapstructure:"clientSecret"`
	RedirectURL  string `mapstructure:"redirectURL"`
	AuthURL      string `mapstructure:"AuthURL"`
	TokenURL     string `mapstructure:"TokenURL"`
}

func loadConfig() (*Config, error) {
	v := viper.New()

	v.SetConfigName("config")
	v.AddConfigPath(".")
	v.SetConfigType("yaml")
	v.AutomaticEnv()
	v.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))
	v.SetEnvPrefix("DNSIFY")
	if err := v.ReadInConfig(); err != nil {
		if _, ok := err.(viper.ConfigFileNotFoundError); ok {
			slog.Error("Config file not found", "Error", err)
		} else {
			return nil, err
		}
	}

	var config Config
	if err := v.Unmarshal(&config); err != nil {
		return nil, err
	}
	return &config, nil
}
