package mock

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"log/slog"
	"net/http"
	"strings"
	"time"
)

func base64UrlEncode(data []byte) string {
	encoded := base64.StdEncoding.EncodeToString(data)
	encoded = strings.ReplaceAll(encoded, "+", "-")
	encoded = strings.ReplaceAll(encoded, "/", "_")
	return strings.TrimRight(encoded, "=")
}

func generateMockIDToken() (string, error) {
	header := map[string]string{
		"alg": "HS256",
		"typ": "JWT",
	}

	headerBytes, err := json.Marshal(header)
	if err != nil {
		return "", err
	}
	currentTime := time.Now()
	issuedAt := currentTime.Unix()
	expiryTime := currentTime.Add(1 * time.Hour).Unix()

	claims := map[string]interface{}{
		"iss":                "oauth2.mock.dnsify",
		"sub":                "1234567890",
		"aud":                "client.dnsify",
		"exp":                expiryTime,
		"nbf":                issuedAt,
		"iat":                issuedAt,
		"jti":                "random-jwt-id", // JWT ID, can be any unique value
		"name":               "John Doe",
		"upn":                "jdoe",
		"preferred_username": "jdoe",
		"email":              "test@test.com",
	}
	claimsBytes, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}

	encodedHeader := base64UrlEncode(headerBytes)
	encodedClaims := base64UrlEncode(claimsBytes)

	// Create the signature
	secret := "mockSecret"
	signature := hmac.New(sha256.New, []byte(secret))
	signature.Write([]byte(encodedHeader + "." + encodedClaims))
	encodedSignature := base64UrlEncode(signature.Sum(nil))

	return encodedHeader + "." + encodedClaims + "." + encodedSignature, nil
}

func MockOAuth2Server() *http.Server {
	mux := http.NewServeMux()
	mux.HandleFunc("/auth", func(w http.ResponseWriter, r *http.Request) {
		// Always redirect to the callback URL with a fixed code
		http.Redirect(w, r, r.URL.Query().Get("redirect_uri")+"?code=mockcode"+"&state="+r.URL.Query().Get("state"), http.StatusFound)
	})
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		// Always return a valid token
		w.Header().Set("Content-Type", "application/json")

		idToken, err := generateMockIDToken()
		if err != nil {
			slog.Error("Error generating mock id token", "error", err.Error())
		}
		w.Write([]byte(`{"access_token": "mocktoken", "id_token": "` + idToken + `", "token_type": "bearer"}`))
	})

	mux.HandleFunc("/introspect", func(w http.ResponseWriter, r *http.Request) {
		// Always return that the token is active
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"active": true}`))
	})
	return &http.Server{
		Addr:    "localhost:9999",
		Handler: mux,
	}
}
