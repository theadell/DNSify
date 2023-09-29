package main

import (
	"html/template"
	"log"

	"github.com/alexedwards/scs/v2"
	"golang.org/x/oauth2"
)

type App struct {
	config         HTTPServerConfig
	sessionManager *scs.SessionManager
	oauthClient    *oauth2.Config
	templateCache  map[string]*template.Template
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

	app := &App{
		sessionManager: sessionManager,
		oauthClient:    oauth2Clinet,
	}

	app.RunServer()
}
