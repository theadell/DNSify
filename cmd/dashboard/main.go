package main

import (
	"html/template"
	"log"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"

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
	server         *http.Server
}

func main() {

	cfg, err := loadConfig()
	if err != nil {
		log.Fatal(err)
	}
	sessionManager := NewSessionManager(cfg.HTTPServerConfig.SecureCookie)
	oauth2Clinet := &oauth2.Config{
		ClientID:     cfg.OAuth2ClientConfig.ClientID,
		ClientSecret: cfg.OAuth2ClientConfig.ClientSecret,
		RedirectURL:  cfg.OAuth2ClientConfig.RedirectURL,
		Scopes:       []string{"openid", "microprofile-jwt"},
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
	stopChan := make(chan os.Signal, 1)
	signal.Notify(stopChan, os.Interrupt, syscall.SIGTERM)

	go func() {
		if err := app.RunServer(); err != nil && err != http.ErrServerClosed {
			slog.Error("Server error", "error", err)
		}
	}()

	select {
	case sig := <-stopChan:
		slog.Info("Received stop signal", "signal", sig)
		app.GracefulShutdown()
	}
	slog.Info("Application has stopped")

}
