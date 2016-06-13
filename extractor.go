package simpletoken

import (
	"fmt"
	stdhttp "net/http"
	"strings"

	"github.com/dgrijalva/jwt-go"
	"github.com/go-kit/kit/log"
	kithttp "github.com/go-kit/kit/transport/http"
	"golang.org/x/net/context"
)

const authorizationHeader = "Authorization"
const bearer = "bearer"

// Attempts to extract the token on every request
func tokenExtractor(logger log.Logger, secret []byte) kithttp.RequestFunc {
	return func(ctx context.Context, r *stdhttp.Request) context.Context {
		authHeader := r.Header.Get(authorizationHeader)
		if authHeader == "" {
			return ctx
		}

		authHeaderParts := strings.Split(authHeader, " ")
		if len(authHeaderParts) != 2 || strings.ToLower(authHeaderParts[0]) != bearer {
			return ctx
		}

		token, err := jwt.Parse(authHeaderParts[1], func(token *jwt.Token) (interface{}, error) {
			return secret, nil
		})
		if err != nil {
			logger.Log("err", fmt.Sprintf("Could not decode token. %s:", authHeaderParts[1]))
			return ctx
		}

		if jwt.SigningMethodRS256.Alg() != token.Header["alg"] {
			logger.Log("err", fmt.Sprintf("Token signing method mismatch: expected %[1]v, got %[2]v", jwt.SigningMethodRS256.Alg(), token.Header["alg"]))
			return ctx
		}

		if !token.Valid {
			logger.Log("err", fmt.Sprintf("Invalid token: %s", authHeaderParts[1]))
			return ctx
		}

		ctx = context.WithValue(ctx, "user", token)
		return ctx
	}
}
