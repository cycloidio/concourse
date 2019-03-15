package tsa

import (
	"crypto/rsa"
	"time"

	"github.com/dgrijalva/jwt-go"
)

//go:generate counterfeiter . TokenGenerator
type TokenGenerator interface {
	GenerateSystemToken() (string, error)
	GenerateTeamToken(teamName string) (string, error)
}

type tokenGenerator struct {
	signingKey *rsa.PrivateKey
}

func NewTokenGenerator(signingKey *rsa.PrivateKey) TokenGenerator {
	return &tokenGenerator{signingKey: signingKey}
}

func (tk *tokenGenerator) GenerateSystemToken() (string, error) {
	exp := time.Now().Add(time.Hour)
	jwtToken := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
		"exp":    exp.Unix(),
		"system": true,
	})

	return jwtToken.SignedString(tk.signingKey)
}

func (tk *tokenGenerator) GenerateTeamToken(teamName string) (string, error) {
	exp := time.Now().Add(time.Hour)
	jwtToken := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
		"exp":       exp.Unix(),
		"teamName":  teamName,
		"teams":     []string{teamName},
		"is_admin": false,
		/// Fix generate token to match the key looked in atc/api/accessor/accessor.go TeamNames()
		/// This have already been patched in CC version 5.0
		/// https://github.com/concourse/atc/commit/ac4b08b719648e3c84ad25a22f421c5c779d0d2f#diff-0d9c12f1c7362814d4f2080cc6e623adR57
		/// https://github.com/concourse/concourse/commit/c20d533e0cfd52ee0e8cef4a03d3e99b7fac38af#diff-ad3c8fe4712cc78ba24358cb0c3137d8R38
		//"isAdmin":  false,
	})

	return jwtToken.SignedString(tk.signingKey)
}
