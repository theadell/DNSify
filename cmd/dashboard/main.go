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
	"github.com/theadell/dnsify/internal/apikeymanager"
	"github.com/theadell/dnsify/internal/auth"
	"github.com/theadell/dnsify/internal/dnsservice"
	"github.com/theadell/dnsify/ui"
)

type App struct {
	config         HTTPServerConfig
	sessionManager *scs.SessionManager
	idp            *auth.Idp
	keyManager     apikeymanager.APIKeyManager
	templateCache  map[string]*template.Template
	dnsClient      dnsservice.Service
	server         *http.Server
}

func main() {
	cfg, err := loadConfig()
	if err != nil {
		log.Fatalf("Error loading config: %v", err)
	}

	sessionManager := NewSessionManager(cfg.HTTPServerConfig.SecureCookie)
	// toggle flags
	var useMockDNS, useMockOAuth bool
	flag.BoolVar(&useMockDNS, "mockdns", false, "Use mock DNS client")
	flag.BoolVar(&useMockOAuth, "mockoauth", false, "Use mock OAuth2 server")
	flag.Parse()

	oauth2Client := SetupIdp(cfg, sessionManager, useMockOAuth)

	bindClient, err := setupDNSClient(cfg, useMockDNS)
	if err != nil {
		log.Fatalf("Error setting up DNS client: %v", err)
	}
	apikeymanager, err := apikeymanager.NewFileAPIKeyManager("./keys.json")
	if err != nil {
		log.Fatalf("Error setting up api keys manager: %v", err)
	}
	app := &App{
		config:         cfg.HTTPServerConfig,
		sessionManager: sessionManager,
		idp:            oauth2Client,
		keyManager:     apikeymanager,
		dnsClient:      bindClient,
		templateCache:  loadTemplates(ui.TemplatesFS),
	}

	handleSignals(app)

	if err := app.RunServer(); err != nil && err != http.ErrServerClosed {
		log.Fatalf("Server error: %v", err)
	}
	slog.Info("Application has stopped")
}

func SetupIdp(cfg *Config, sessionManager *scs.SessionManager, useMockOAuth bool) *auth.Idp {

	if useMockOAuth {
		return auth.NewMockIdp(&cfg.OAuth2ClientConfig, sessionManager)
	}
	return auth.NewIdp(&cfg.OAuth2ClientConfig, sessionManager)
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
