package main

import (
	"net/http"
	"time"

	"github.com/alexedwards/scs/v2"
	"github.com/alexedwards/scs/v2/memstore"
)

func NewSessionManager() *scs.SessionManager {
	sessionManager := scs.New()
	sessionManager.Lifetime = 1 * time.Hour
	sessionManager.Cookie.Name = "session_id"
	sessionManager.Cookie.HttpOnly = true
	sessionManager.Cookie.SameSite = http.SameSiteLaxMode
	sessionManager.Store = memstore.New()
	return sessionManager
}
