package main

import (
	"flag"
	"html/template"
	"log"
	"net/http"
	"sync"
	"time"

	"github.com/alexedwards/scs/v2"
	"github.com/alexedwards/scs/v2/memstore"
	"github.com/miekg/dns"
	"github.com/theadell/dns-api/internal/dnsutils"
	"golang.org/x/oauth2"
)

type App struct {
	ZoneFilePath  string
	TSIGKey       string
	TSIGSecret    string
	SyncEnabled   bool
	Port          uint
	SessionStore  *scs.SessionManager
	OauthClient   *oauth2.Config
	TemplateCache map[string]*template.Template
	DnsClient     *dns.Client
	RecordCache   RecordCache
	syncCh        chan struct{} // channel used as non-blocking semaphore

}

func main() {

	zoneFilePath := flag.String("zoneFile", "./db.example.com", "Path to Zone-file")
	key := flag.String("TSIGKey ", "tsig-key.", "the key name of the TSIG secret")
	secret := flag.String("TSIGSecret", "some-secret", "TSIG secret")
	syncEnabled := flag.Bool("sync", false, "Enable automatic sync of zone fikes after a dynamic update")
	port := flag.Uint("port", 8080, "Port at which to bind the server")

	clientId := flag.String("OAuth2 Client Id", "dns", "OAuth 2.0 & OpenId client id")
	clientSecret := flag.String("clientSecret", "secret", "OAuth 2.0 client secret")
	redirectURL := flag.String("redirectURI", "https://dns.rusty-leipzig.com/oauth/redirect", "OAuth 2.0 redirectURL")
	flag.Parse()
	sessionManager := scs.New()
	sessionManager.Lifetime = 1 * time.Hour // Sessions last for 1 hour
	sessionManager.Cookie.Name = "session_id"
	sessionManager.Cookie.HttpOnly = true
	sessionManager.Cookie.SameSite = http.SameSiteLaxMode
	sessionManager.Store = memstore.New()

	oauth2Clinet := &oauth2.Config{
		ClientID:     *clientId,
		ClientSecret: *clientSecret,
		Scopes:       []string{"openid"},
		Endpoint: oauth2.Endpoint{
			AuthURL:  "https://accounts.itemis-leipzig.de/realms/Leipzig/protocol/openid-connect/auth",
			TokenURL: "https://accounts.itemis-leipzig.de/realms/Leipzig/protocol/openid-connect/token",
		},
		RedirectURL: *redirectURL,
	}
	app := &App{
		ZoneFilePath:  *zoneFilePath,
		TSIGKey:       *key,
		TSIGSecret:    *secret,
		SyncEnabled:   *syncEnabled,
		Port:          *port,
		SessionStore:  sessionManager,
		TemplateCache: loadTemplates(),
		OauthClient:   oauth2Clinet,
		DnsClient:     new(dns.Client),
		RecordCache:   RecordCache{mu: &sync.RWMutex{}},
		syncCh:        make(chan struct{}, 1),
	}
	// Setup TSIG authentication.
	app.DnsClient.TsigSecret = map[string]string{app.TSIGKey: app.TSIGSecret}
	records, err := dnsutils.ReadRecords(app.ZoneFilePath)
	if err != nil {
		log.Fatalf("Failed to read initial records: %v", err)
	}
	app.RecordCache.set(records)
	go app.watchFileZone()
	app.RunServer()
}
