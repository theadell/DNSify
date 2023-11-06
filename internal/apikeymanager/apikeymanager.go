package apikeymanager

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"time"
)

type APIKey struct {
	UserID    string    `json:"userId"`
	Label     string    `json:"label"`
	Key       string    `json:"apiKey"`
	CreatedAt time.Time `json:"createdAt"`
}

type APIKeyManager interface {
	CreateKey(ctx context.Context, userID, label string) (APIKey, error)
	GetKeys(ctx context.Context, userID string) ([]APIKey, error)
	DeleteKey(ctx context.Context, userID, label string) error
}

func generateSecureKey(length int) (string, error) {
	bytes := make([]byte, length)
	_, err := rand.Read(bytes)
	if err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(bytes), nil
}
