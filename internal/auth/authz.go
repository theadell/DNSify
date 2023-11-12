package auth

import (
	"fmt"
	"log/slog"
	"strings"
)

var ErrUnauthorizedDomain = fmt.Errorf("unauthorized email domain")

// CheckUserAuthorization checks if the user with the given email is authorized.
func (idp *Idp) CheckUserAuthorization(email string) error {
	if !idp.restrictAccess {
		return nil
	}

	idx := strings.LastIndex(email, "@")
	if idx <= 0 {
		// Log the invalid email format internally, but do not return an error to the caller
		slog.Info("Invalid email format", slog.String("email", email))
		return nil
	}

	domain := email[idx+1:]
	for _, org := range idp.whiteList {
		if strings.EqualFold(domain, org) {
			return nil
		}
	}

	return fmt.Errorf("%w: %s", ErrUnauthorizedDomain, domain)
}
