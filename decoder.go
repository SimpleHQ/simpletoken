package simpletoken

import (
	stdhttp "net/http"

	"github.com/dgrijalva/jwt-go"
	kithttp "github.com/go-kit/kit/transport/http"
	"golang.org/x/net/context"
)

// Closure to allow us to protect endpoints by validating token exists
func decodeProtected(decoder kithttp.DecodeRequestFunc) kithttp.DecodeRequestFunc {
	return func(ctx context.Context, r *stdhttp.Request) (request interface{}, err error) {
		if _, ok := ctx.Value("user").(*jwt.Token); ok != true {
			return nil, NewError(stdhttp.StatusUnauthorized, "Unauthorized.")
		}
		return decoder(ctx, r)
	}
}
