package auth

import (
	"strings"

	"github.com/alexedwards/scs/v2"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/endpoints"
)

type LoginPromptData struct {
	Text     string
	Provider string
}

type Idp struct {
	oauth2.Config
	provider        string
	restrictAccess  bool
	whiteList       []string
	sessionManager  *scs.SessionManager
	LoginPromptData LoginPromptData
}

type OAuth2ClientConfig struct {
	ClientID          string `mapstructure:"clientID"`
	ClientSecret      string `mapstructure:"clientSecret"`
	RedirectURL       string `mapstructure:"redirectURL"`
	AuthURL           string `mapstructure:"authURL"`
	TokenURL          string `mapstructure:"tokenURL"`
	Scopes            []string
	Provider          string   `mapstructure:"provider"`
	AuthorizedDomains []string `mapstructure:"authorizedDomains"`
	Tenant            string
	Domain            string
	LoginText         string
}

func NewIdp(config *OAuth2ClientConfig, sessionManager *scs.SessionManager) *Idp {

	endpoint := oauth2.Endpoint{}
	provider := strings.ToLower(config.Provider)
	text := "Sign in with " + provider
	lpd := LoginPromptData{Text: text, Provider: provider}

	switch provider {
	case "google":
		endpoint = endpoints.Google
	case "facebook":
		endpoint = endpoints.Facebook
	case "amazon":
		endpoint = endpoints.Amazon
	case "gitlab":
		endpoint = endpoints.GitLab
	case "github":
		endpoint = endpoints.GitHub
	case "bitbucket":
		endpoint = endpoints.Bitbucket
	case "microsoft":
		endpoint = endpoints.Microsoft
	case "azuread":
		endpoint = endpoints.AzureAD(config.Tenant)
	case "awscognito":
		endpoint = endpoints.AWSCognito(config.Domain)
	default:
		endpoint.AuthURL = config.AuthURL
		endpoint.TokenURL = config.TokenURL
		text = "Sign in with your DNSify account"
		lpd.Provider = "default"
	}

	if config.Scopes == nil {
		config.Scopes = []string{"openid"}
	}

	oauthConfig := oauth2.Config{
		ClientID:     config.ClientID,
		ClientSecret: config.ClientSecret,
		RedirectURL:  config.RedirectURL,
		Endpoint:     endpoint,
		Scopes:       config.Scopes,
	}
	if config.LoginText != "" {
		text = config.LoginText
	}
	lpd.Text = text
	idp := &Idp{
		Config:          oauthConfig,
		provider:        provider,
		whiteList:       config.AuthorizedDomains,
		sessionManager:  sessionManager,
		LoginPromptData: lpd,
	}
	if config.AuthorizedDomains != nil {
		idp.restrictAccess = true
	}

	return idp
}
