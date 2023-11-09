package auth

import (
	"strings"
)

func (idp *Idp) isUserAuthorized(email string) bool {
	if !idp.restrictAccess {
		return true
	}
	idx := strings.LastIndex(email, "@")
	if idx <= 0 {
		return false
	}
	domain := email[idx+1:]
	for _, org := range idp.whiteList {
		if strings.EqualFold(domain, org) {
			return true
		}
	}
	return false
}
