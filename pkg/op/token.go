package op

import (
	"context"
	"net/http"
	"time"

	"github.com/trustasia-com/oidc/pkg/crypto"
	"github.com/trustasia-com/oidc/pkg/oidc"
	"github.com/trustasia-com/oidc/pkg/strings"
)

type TokenCreator interface {
	Issuer(r *http.Request) string
	Signer(r *http.Request) (Signer, error)
	Storage() Storage
	Crypto() Crypto
}

type TokenRequest interface {
	GetSubject() string
	GetAudience() []string
	GetScopes() []string
}

func CreateTokenResponse(ctx context.Context, r *http.Request, request IDTokenRequest, client Client, creator TokenCreator, createAccessToken bool, code, refreshToken string) (*oidc.AccessTokenResponse, error) {
	var accessToken, newRefreshToken string
	var validity time.Duration
	if createAccessToken {
		var err error
		accessToken, newRefreshToken, validity, err = CreateAccessToken(ctx, r, request, client.AccessTokenType(), creator, client, refreshToken)
		if err != nil {
			return nil, err
		}
	}
	singer, err := creator.Signer(r)
	if err != nil {
		return nil, err
	}
	idToken, err := CreateIDToken(ctx, creator.Issuer(r), request, client.IDTokenLifetime(), accessToken, code, creator.Storage(), singer, client)
	if err != nil {
		return nil, err
	}

	var state string
	if authRequest, ok := request.(AuthRequest); ok {
		err = creator.Storage().DeleteAuthRequest(ctx, authRequest.GetCode())
		if err != nil {
			return nil, err
		}
		state = authRequest.GetState()
	}

	exp := uint64(validity.Seconds())
	return &oidc.AccessTokenResponse{
		AccessToken:  accessToken,
		IDToken:      idToken,
		RefreshToken: newRefreshToken,
		TokenType:    oidc.BearerToken,
		ExpiresIn:    exp,
		State:        state,
	}, nil
}

func createTokens(ctx context.Context, tokenRequest TokenRequest, storage Storage, refreshToken string, client Client) (id, newRefreshToken string, exp time.Time, err error) {
	if needsRefreshToken(tokenRequest, client) {
		return storage.CreateAccessAndRefreshTokens(ctx, tokenRequest, refreshToken)
	}
	id, exp, err = storage.CreateAccessToken(ctx, tokenRequest)
	return
}

func needsRefreshToken(tokenRequest TokenRequest, client Client) bool {
	switch req := tokenRequest.(type) {
	case AuthRequest:
		return strings.Contains(req.GetScopes(), oidc.ScopeOfflineAccess) && req.GetResponseType() == oidc.ResponseTypeCode && ValidateGrantType(client, oidc.GrantTypeRefreshToken)
	case RefreshTokenRequest:
		return true
	default:
		return false
	}
}

func CreateAccessToken(ctx context.Context, r *http.Request, tokenRequest TokenRequest, accessTokenType AccessTokenType, creator TokenCreator, client Client, refreshToken string) (accessToken, newRefreshToken string, validity time.Duration, err error) {
	id, newRefreshToken, exp, err := createTokens(ctx, tokenRequest, creator.Storage(), refreshToken, client)
	if err != nil {
		return "", "", 0, err
	}
	var clockSkew time.Duration
	if client != nil {
		clockSkew = client.ClockSkew()
	}
	validity = exp.Add(clockSkew).Sub(time.Now().UTC())

	singer, err := creator.Signer(r)
	if err != nil {
		return "", "", 0, err
	}
	if accessTokenType == AccessTokenTypeJWT {
		accessToken, err = CreateJWT(ctx, creator.Issuer(r), tokenRequest, exp, id, singer, client, creator.Storage())
		return
	}
	accessToken, err = CreateBearerToken(id, tokenRequest.GetSubject(), creator.Crypto())
	return
}

func CreateBearerToken(tokenID, subject string, crypto Crypto) (string, error) {
	return crypto.Encrypt(tokenID + ":" + subject)
}

func CreateJWT(ctx context.Context, issuer string, tokenRequest TokenRequest, exp time.Time, id string, signer Signer, client Client, storage Storage) (string, error) {
	claims := oidc.NewAccessTokenClaims(issuer, tokenRequest.GetSubject(), tokenRequest.GetAudience(), exp, id, client.GetID(), client.ClockSkew())
	if client != nil {
		restrictedScopes := client.RestrictAdditionalAccessTokenScopes()(tokenRequest.GetScopes())
		privateClaims, err := storage.GetPrivateClaimsFromScopes(ctx, tokenRequest.GetSubject(), client.GetID(), removeUserinfoScopes(restrictedScopes))
		if err != nil {
			return "", err
		}
		claims.SetPrivateClaims(privateClaims)
		claims.SetScopes(tokenRequest.GetScopes())
	}
	return crypto.Sign(claims, signer.Signer())
}

type IDTokenRequest interface {
	GetAMR() []string
	GetAudience() []string
	GetAuthTime() time.Time
	GetClientID() string
	GetScopes() []string
	GetSubject() string
}

func CreateIDToken(ctx context.Context, issuer string, request IDTokenRequest, validity time.Duration, accessToken, code string, storage Storage, signer Signer, client Client) (string, error) {
	exp := time.Now().UTC().Add(client.ClockSkew()).Add(validity)
	var acr, nonce string
	if authRequest, ok := request.(AuthRequest); ok {
		acr = authRequest.GetACR()
		nonce = authRequest.GetNonce()
	}
	claims := oidc.NewIDTokenClaims(issuer, request.GetSubject(), request.GetAudience(), exp, request.GetAuthTime(), nonce, acr, request.GetAMR(), request.GetClientID(), client.ClockSkew())
	scopes := client.RestrictAdditionalIdTokenScopes()(request.GetScopes())
	if accessToken != "" {
		atHash, err := oidc.ClaimHash(accessToken, signer.SignatureAlgorithm())
		if err != nil {
			return "", err
		}
		claims.SetAccessTokenHash(atHash)
		if !client.IDTokenUserinfoClaimsAssertion() {
			scopes = removeUserinfoScopes(scopes)
		}
	}
	if len(scopes) > 0 {
		userInfo := oidc.NewUserInfo()
		err := storage.SetUserinfoFromScopes(ctx, userInfo, request.GetSubject(), request.GetClientID(), scopes)
		if err != nil {
			return "", err
		}
		claims.SetUserinfo(userInfo)
	}
	if code != "" {
		codeHash, err := oidc.ClaimHash(code, signer.SignatureAlgorithm())
		if err != nil {
			return "", err
		}
		claims.SetCodeHash(codeHash)
	}

	return crypto.Sign(claims, signer.Signer())
}

func removeUserinfoScopes(scopes []string) []string {
	newScopeList := make([]string, 0, len(scopes))
	for _, scope := range scopes {
		switch scope {
		case oidc.ScopeProfile,
			oidc.ScopeEmail,
			oidc.ScopeAddress,
			oidc.ScopePhone:
			continue
		default:
			newScopeList = append(newScopeList, scope)
		}
	}
	return newScopeList
}
