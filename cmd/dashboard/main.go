package main

import (
	"flag"
	"html/template"
	"log"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"

	"github.com/alexedwards/scs/v2"
	"github.com/theadell/dnsify/internal/dnsservice"
	"github.com/theadell/dnsify/internal/mock"
	"github.com/theadell/dnsify/ui"
	"golang.org/x/oauth2"
)

type App struct {
	config         HTTPServerConfig
	sessionManager *scs.SessionManager
	oauthClient    *oauth2.Config
	templateCache  map[string]*template.Template
	dnsClient      dnsservice.Service
	server         *http.Server
}

func main() {
	cfg, err := loadConfig()
	if err != nil {
		log.Fatalf("Error loading config: %v", err)
	}

	// toggle flags
	var useMockDNS, useMockOAuth bool
	flag.BoolVar(&useMockDNS, "mockdns", false, "Use mock DNS client")
	flag.BoolVar(&useMockOAuth, "mockoauth", false, "Use mock OAuth2 server")
	flag.Parse()

	oauth2Client := setupOAuthClient(cfg, useMockOAuth)

	bindClient, err := setupDNSClient(cfg, useMockDNS)
	if err != nil {
		log.Fatalf("Error setting up DNS client: %v", err)
	}

	sessionManager := NewSessionManager(cfg.HTTPServerConfig.SecureCookie)
	app := &App{
		config:         cfg.HTTPServerConfig,
		sessionManager: sessionManager,
		oauthClient:    oauth2Client,
		dnsClient:      bindClient,
		templateCache:  loadTemplates(ui.TemplatesFS),
	}

	handleSignals(app)

	if err := app.RunServer(); err != nil && err != http.ErrServerClosed {
		log.Fatalf("Server error: %v", err)
	}
	slog.Info("Application has stopped")
}

func setupOAuthClient(cfg *Config, useMockOAuth bool) *oauth2.Config {

	if useMockOAuth {
		go mock.MockOAuth2Server().ListenAndServe()
		return &oauth2.Config{
			ClientID:     cfg.OAuth2ClientConfig.ClientID,
			ClientSecret: cfg.OAuth2ClientConfig.ClientSecret,
			RedirectURL:  cfg.OAuth2ClientConfig.RedirectURL,
			Scopes:       []string{"openid", "microprofile-jwt"},
			Endpoint: oauth2.Endpoint{
				AuthURL:  "http://localhost:9999/auth",
				TokenURL: "http://localhost:9999/token",
			},
		}
	}

	return &oauth2.Config{
		ClientID:     cfg.OAuth2ClientConfig.ClientID,
		ClientSecret: cfg.OAuth2ClientConfig.ClientSecret,
		RedirectURL:  cfg.OAuth2ClientConfig.RedirectURL,
		Scopes:       []string{"openid", "microprofile-jwt"},
		Endpoint: oauth2.Endpoint{
			AuthURL:  cfg.OAuth2ClientConfig.AuthURL,
			TokenURL: cfg.OAuth2ClientConfig.TokenURL,
		},
	}
}

func setupDNSClient(cfg *Config, useMockDNS bool) (dnsservice.Service, error) {

	if useMockDNS {
		return dnsservice.NewMockClientWithTestRecords(), nil
	}
	return dnsservice.NewClient(cfg.DNSClientConfig)
}

func handleSignals(app *App) {
	stopChan := make(chan os.Signal, 1)
	signal.Notify(stopChan, os.Interrupt, syscall.SIGTERM)

	go func() {
		sig := <-stopChan
		slog.Info("Received stop signal", "signal", sig)
		app.GracefulShutdown()
	}()
}
