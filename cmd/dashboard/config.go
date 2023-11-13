package main

import (
	"log/slog"
	"strings"
	"time"

	"github.com/spf13/viper"
	"github.com/theadell/dnsify/internal/auth"
	"github.com/theadell/dnsify/internal/dnsservice"
)

type Config struct {
	DNSClientConfig    dnsservice.DNSConfig    `mapstructure:"dns"`
	HTTPServerConfig   HTTPServerConfig        `mapstructure:"httpServer"`
	OAuth2ClientConfig auth.OAuth2ClientConfig `mapstructure:"oauth2Client"`
}

type HTTPServerConfig struct {
	Host         string `mapstructure:"host"`
	Port         uint   `mapstructure:"port"`
	SecureCookie bool   `mapstructure:"secureCookie"`
	pushInterval time.Duration
}

func loadConfig() (*Config, error) {
	v := viper.New()

	v.SetConfigName("config")
	v.AddConfigPath(".")
	v.SetConfigType("yaml")
	v.AutomaticEnv()
	v.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))
	v.SetEnvPrefix("DNSIFY")

	// TODO: Unmarshal non-bound environment variables
	// adjust when viper provides a solution to https://github.com/spf13/viper/issues/761
	// workaround: manual binding for commented out feilds in config.yaml
	bindEnvVars(v)

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

func bindEnvVars(v *viper.Viper) {
	v.BindEnv("dns.server.addr", "DNS_SERVER_ADDR")
	v.BindEnv("dns.server.zone", "DNS_SERVER_ZONE")
	v.BindEnv("dns.server.tsigKey", "DNS_SERVER_TSIGKEY")
	v.BindEnv("dns.server.tsigSecret", "DNS_SERVER_TSIGSECRET")
	v.BindEnv("dns.client.syncInterval", "DNS_CLIENT_SYNCINTERVAL")
	v.BindEnv("dns.client.healthCheckInterval", "DNS_CLIENT_HEALTHCHECKINTERVAL")
	v.BindEnv("dns.client.ipv4", "DNS_CLIENT_IPV4")
	v.BindEnv("dns.client.ipv6", "DNS_CLIENT_IPV6")
	v.BindEnv("dns.client.guards.immutable", "DNS_CLIENT_GUARDS_IMMUTABLE")
	v.BindEnv("dns.client.guards.admin_only", "DNS_CLIENT_GUARDS_ADMIN_ONLY")

	v.BindEnv("httpServer.host", "HTTPSERVER_HOST")
	v.BindEnv("httpServer.port", "HTTPSERVER_PORT")
	v.BindEnv("httpServer.secureCookie", "HTTPSERVER_SECURECOOKIE")

	v.BindEnv("oauth2Client.provider", "OAUTH2CLIENT_PROVIDER")
	v.BindEnv("oauth2Client.authURL", "OAUTH2CLIENT_AUTHURL")
	v.BindEnv("oauth2Client.tokenURL", "OAUTH2CLIENT_TOKENURL")
	v.BindEnv("oauth2Client.clientID", "OAUTH2CLIENT_CLIENTID")
	v.BindEnv("oauth2Client.clientSecret", "OAUTH2CLIENT_CLIENTSECRET")
	v.BindEnv("oauth2Client.scopes", "OAUTH2CLIENT_SCOPES")
	v.BindEnv("oauth2Client.redirectURL", "OAUTH2CLIENT_REDIRECTURL")
	v.BindEnv("oauth2Client.tenant", "OAUTH2CLIENT_TENANT")
	v.BindEnv("oauth2Client.domain", "OAUTH2CLIENT_DOMAIN")
	v.BindEnv("oauth2Client.authorizedDomains", "OAUTH2CLIENT_AUTHORIZEDDOMAINS")
	v.BindEnv("oauth2Client.loginText", "OAUTH2CLIENT_LOGINTEXT")
}
