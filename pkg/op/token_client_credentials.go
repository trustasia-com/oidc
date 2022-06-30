package op

import (
	"context"
	"net/http"
	"net/url"

	httphelper "github.com/trustasia-com/oidc/pkg/http"
	"github.com/trustasia-com/oidc/pkg/oidc"
)

//ClientCredentialsExchange handles the OAuth 2.0 client_credentials grant, including
//parsing, validating, authorizing the client and finally returning a token
func ClientCredentialsExchange(w http.ResponseWriter, r *http.Request, exchanger Exchanger) {
	request, err := ParseClientCredentialsRequest(r, exchanger.Decoder())
	if err != nil {
		RequestError(w, r, err)
	}

	validatedRequest, client, err := ValidateClientCredentialsRequest(r.Context(), request, exchanger)
	if err != nil {
		RequestError(w, r, err)
		return
	}

	resp, err := CreateClientCredentialsTokenResponse(r.Context(), r, validatedRequest, exchanger, client)
	if err != nil {
		RequestError(w, r, err)
		return
	}

	httphelper.MarshalJSON(w, resp)
}

//ParseClientCredentialsRequest parsed the http request into a oidc.ClientCredentialsRequest
func ParseClientCredentialsRequest(r *http.Request, decoder httphelper.Decoder) (*oidc.ClientCredentialsRequest, error) {
	err := r.ParseForm()
	if err != nil {
		return nil, oidc.ErrInvalidRequest().WithDescription("error parsing form").WithParent(err)
	}

	request := new(oidc.ClientCredentialsRequest)
	err = decoder.Decode(request, r.Form)
	if err != nil {
		return nil, oidc.ErrInvalidRequest().WithDescription("error decoding form").WithParent(err)
	}

	if clientID, clientSecret, ok := r.BasicAuth(); ok {
		clientID, err = url.QueryUnescape(clientID)
		if err != nil {
			return nil, oidc.ErrInvalidClient().WithDescription("invalid basic auth header").WithParent(err)
		}

		clientSecret, err = url.QueryUnescape(clientSecret)
		if err != nil {
			return nil, oidc.ErrInvalidClient().WithDescription("invalid basic auth header").WithParent(err)
		}

		request.ClientID = clientID
		request.ClientSecret = clientSecret
	}

	return request, nil
}

//ValidateClientCredentialsRequest validates the refresh_token request parameters including authorization check of the client
//and returns the data representing the original auth request corresponding to the refresh_token
func ValidateClientCredentialsRequest(ctx context.Context, request *oidc.ClientCredentialsRequest, exchanger Exchanger) (TokenRequest, Client, error) {
	storage, ok := exchanger.Storage().(ClientCredentialsStorage)
	if !ok {
		return nil, nil, oidc.ErrUnsupportedGrantType().WithDescription("client_credentials grant not supported")
	}

	client, err := AuthorizeClientCredentialsClient(ctx, request, exchanger)
	if err != nil {
		return nil, nil, err
	}

	tokenRequest, err := storage.ClientCredentialsTokenRequest(ctx, request.ClientID, request.Scope)
	if err != nil {
		return nil, nil, err
	}

	return tokenRequest, client, nil
}

func AuthorizeClientCredentialsClient(ctx context.Context, request *oidc.ClientCredentialsRequest, exchanger Exchanger) (Client, error) {
	if err := AuthorizeClientIDSecret(ctx, request.ClientID, request.ClientSecret, exchanger.Storage()); err != nil {
		return nil, err
	}

	client, err := exchanger.Storage().GetClientByClientID(ctx, request.ClientID)
	if err != nil {
		return nil, oidc.ErrInvalidClient().WithParent(err)
	}

	if !ValidateGrantType(client, oidc.GrantTypeClientCredentials) {
		return nil, oidc.ErrUnauthorizedClient()
	}

	return client, nil
}

func CreateClientCredentialsTokenResponse(ctx context.Context, r *http.Request, tokenRequest TokenRequest, creator TokenCreator, client Client) (*oidc.AccessTokenResponse, error) {
	accessToken, _, validity, err := CreateAccessToken(ctx, r, tokenRequest, AccessTokenTypeJWT, creator, client, "")
	if err != nil {
		return nil, err
	}

	return &oidc.AccessTokenResponse{
		AccessToken: accessToken,
		TokenType:   oidc.BearerToken,
		ExpiresIn:   uint64(validity.Seconds()),
	}, nil
}
