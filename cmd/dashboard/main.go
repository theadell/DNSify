package main

import (
	"html/template"
	"log"

	"github.com/alexedwards/scs/v2"
	"github.com/theadell/dns-api/internal/dnsclient"
	"golang.org/x/oauth2"
)

type App struct {
	config         HTTPServerConfig
	sessionManager *scs.SessionManager
	oauthClient    *oauth2.Config
	templateCache  map[string]*template.Template
	bindClient     dnsclient.DNSClient
}

func main() {

	cfg, err := loadConfig()
	if err != nil {
		log.Fatal(err)
	}
	sessionManager := NewSessionManager()
	oauth2Clinet := &oauth2.Config{
		ClientID:     cfg.OAuth2ClientConfig.ClientID,
		ClientSecret: cfg.OAuth2ClientConfig.ClientSecret,
		RedirectURL:  cfg.OAuth2ClientConfig.RedirectURL,
		Scopes:       []string{"openid"},
		Endpoint: oauth2.Endpoint{
			AuthURL:  "https://accounts.itemis-leipzig.de/realms/Leipzig/protocol/openid-connect/auth",
			TokenURL: "https://accounts.itemis-leipzig.de/realms/Leipzig/protocol/openid-connect/token",
		},
	}

	bindClient, err := dnsclient.NewBindClient(cfg.DNSClientConfig)
	if err != nil {
		log.Fatal(err)
	}
	app := &App{
		config:         cfg.HTTPServerConfig,
		sessionManager: sessionManager,
		oauthClient:    oauth2Clinet,
		bindClient:     bindClient,
		templateCache:  loadTemplates(),
	}
	app.RunServer()

}
