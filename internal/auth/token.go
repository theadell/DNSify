package auth

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"log/slog"
	"strings"

	"golang.org/x/oauth2"
)

var ErrInvalidToken = errors.New("Invalid token")

type IdToken map[string]any

func (id IdToken) GetString(claim string) string {
	val, ok := id[claim]
	if !ok {
		return ""
	}
	valString, ok := val.(string)
	if !ok {
		return ""
	}
	return valString
}

func (id IdToken) Exists(claim string) bool {
	_, ok := id[claim]
	return ok
}

func decodeToken(token *oauth2.Token) (IdToken, error) {
	rawIDToken, ok := token.Extra("id_token").(string)
	if !ok {
		slog.Error("id_token was not found in token response")
		return nil, ErrInvalidToken
	}
	parts := strings.Split(rawIDToken, ".")
	if len(parts) != 3 {
		slog.Error("id_token format is not valid JWT")
		return nil, ErrInvalidToken
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, ErrInvalidToken
	}
	var idToken IdToken
	if err := json.Unmarshal(payload, &idToken); err != nil {
		slog.Error("Failed to Unmarshal id_token", "error", err.Error())
		return nil, ErrInvalidToken
	}
	return idToken, nil
}
