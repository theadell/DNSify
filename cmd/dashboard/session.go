package main

import (
	"net/http"
	"time"

	"github.com/alexedwards/scs/v2"
	"github.com/alexedwards/scs/v2/memstore"
)

func NewSessionManager(useSecureCookie bool) *scs.SessionManager {
	sessionManager := scs.New()
	sessionManager.Lifetime = 1 * time.Hour
	sessionManager.Cookie.Name = "session_id"
	sessionManager.Cookie.HttpOnly = true
	sessionManager.Cookie.SameSite = http.SameSiteLaxMode
	sessionManager.Store = memstore.New()
	sessionManager.IdleTimeout = 20 * time.Minute
	sessionManager.Cookie.Secure = useSecureCookie
	return sessionManager
}
