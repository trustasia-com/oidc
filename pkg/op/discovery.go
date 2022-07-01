package op

import (
	"net/http"

	httphelper "github.com/trustasia-com/oidc/pkg/http"
	"github.com/trustasia-com/oidc/pkg/oidc"
)

func discoveryHandler(c Configuration, s Signer) func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		Discover(w, CreateDiscoveryConfig(r, c, s))
	}
}

func Discover(w http.ResponseWriter, config *oidc.DiscoveryConfiguration) {
	httphelper.MarshalJSON(w, config)
}

func CreateDiscoveryConfig(r *http.Request, c Configuration, s Signer) *oidc.DiscoveryConfiguration {
	return &oidc.DiscoveryConfiguration{
		Issuer:                                     c.Issuer(r),
		AuthorizationEndpoint:                      c.AuthorizationEndpoint().Absolute(c.Issuer(r)),
		TokenEndpoint:                              c.TokenEndpoint().Absolute(c.Issuer(r)),
		IntrospectionEndpoint:                      c.IntrospectionEndpoint().Absolute(c.Issuer(r)),
		UserinfoEndpoint:                           c.UserinfoEndpoint().Absolute(c.Issuer(r)),
		RevocationEndpoint:                         c.RevocationEndpoint().Absolute(c.Issuer(r)),
		EndSessionEndpoint:                         c.EndSessionEndpoint().Absolute(c.Issuer(r)),
		JwksURI:                                    c.KeysEndpoint().Absolute(c.Issuer(r)),
		ScopesSupported:                            Scopes(c),
		ResponseTypesSupported:                     ResponseTypes(c),
		GrantTypesSupported:                        GrantTypes(c),
		SubjectTypesSupported:                      SubjectTypes(c),
		IDTokenSigningAlgValuesSupported:           SigAlgorithms(s),
		RequestObjectSigningAlgValuesSupported:     RequestObjectSigAlgorithms(c),
		TokenEndpointAuthMethodsSupported:          AuthMethodsTokenEndpoint(c),
		TokenEndpointAuthSigningAlgValuesSupported: TokenSigAlgorithms(c),
		IntrospectionEndpointAuthSigningAlgValuesSupported: IntrospectionSigAlgorithms(c),
		IntrospectionEndpointAuthMethodsSupported:          AuthMethodsIntrospectionEndpoint(c),
		RevocationEndpointAuthSigningAlgValuesSupported:    RevocationSigAlgorithms(c),
		RevocationEndpointAuthMethodsSupported:             AuthMethodsRevocationEndpoint(c),
		ClaimsSupported:                                    SupportedClaims(c),
		CodeChallengeMethodsSupported:                      CodeChallengeMethods(c),
		UILocalesSupported:                                 c.SupportedUILocales(),
		RequestParameterSupported:                          c.RequestObjectSupported(),
	}
}

var DefaultSupportedScopes = []string{
	oidc.ScopeOpenID,
	oidc.ScopeProfile,
	oidc.ScopeEmail,
	oidc.ScopePhone,
	oidc.ScopeAddress,
	oidc.ScopeOfflineAccess,
}

func Scopes(c Configuration) []string {
	return c.GetScopesSupported()
}

func ResponseTypes(c Configuration) []string {
	return []string{
		string(oidc.ResponseTypeCode),
		string(oidc.ResponseTypeIDTokenOnly),
		string(oidc.ResponseTypeIDToken),
	} //TODO: ok for now, check later if dynamic needed
}

func GrantTypes(c Configuration) []oidc.GrantType {
	grantTypes := []oidc.GrantType{
		oidc.GrantTypeCode,
		oidc.GrantTypeImplicit,
	}
	if c.GrantTypeRefreshTokenSupported() {
		grantTypes = append(grantTypes, oidc.GrantTypeRefreshToken)
	}
	if c.GrantTypeClientCredentialsSupported() {
		grantTypes = append(grantTypes, oidc.GrantTypeClientCredentials)
	}
	if c.GrantTypeTokenExchangeSupported() {
		grantTypes = append(grantTypes, oidc.GrantTypeTokenExchange)
	}
	if c.GrantTypeJWTAuthorizationSupported() {
		grantTypes = append(grantTypes, oidc.GrantTypeBearer)
	}
	return grantTypes
}

func SupportedClaims(c Configuration) []string {
	return c.GetSupportedClaims()
}

func SigAlgorithms(s Signer) []string {
	return []string{string(s.SignatureAlgorithm())}
}

func SubjectTypes(c Configuration) []string {
	return []string{"public"} //TODO: config
}

func AuthMethodsTokenEndpoint(c Configuration) []oidc.AuthMethod {
	authMethods := []oidc.AuthMethod{
		oidc.AuthMethodNone,
		oidc.AuthMethodBasic,
	}
	if c.AuthMethodPostSupported() {
		authMethods = append(authMethods, oidc.AuthMethodPost)
	}
	if c.AuthMethodPrivateKeyJWTSupported() {
		authMethods = append(authMethods, oidc.AuthMethodPrivateKeyJWT)
	}
	return authMethods
}

func TokenSigAlgorithms(c Configuration) []string {
	if !c.AuthMethodPrivateKeyJWTSupported() {
		return nil
	}
	return c.TokenEndpointSigningAlgorithmsSupported()
}

func AuthMethodsIntrospectionEndpoint(c Configuration) []oidc.AuthMethod {
	authMethods := []oidc.AuthMethod{
		oidc.AuthMethodBasic,
	}
	if c.AuthMethodPrivateKeyJWTSupported() {
		authMethods = append(authMethods, oidc.AuthMethodPrivateKeyJWT)
	}
	return authMethods
}

func AuthMethodsRevocationEndpoint(c Configuration) []oidc.AuthMethod {
	authMethods := []oidc.AuthMethod{
		oidc.AuthMethodNone,
		oidc.AuthMethodBasic,
	}
	if c.AuthMethodPostSupported() {
		authMethods = append(authMethods, oidc.AuthMethodPost)
	}
	if c.AuthMethodPrivateKeyJWTSupported() {
		authMethods = append(authMethods, oidc.AuthMethodPrivateKeyJWT)
	}
	return authMethods
}

func CodeChallengeMethods(c Configuration) []oidc.CodeChallengeMethod {
	codeMethods := make([]oidc.CodeChallengeMethod, 0, 2)
	codeMethods = append(codeMethods, oidc.CodeChallengeMethodPlain)
	if c.CodeMethodS256Supported() {
		codeMethods = append(codeMethods, oidc.CodeChallengeMethodS256)
	}
	return codeMethods
}

func IntrospectionSigAlgorithms(c Configuration) []string {
	if !c.IntrospectionAuthMethodPrivateKeyJWTSupported() {
		return nil
	}
	return c.IntrospectionEndpointSigningAlgorithmsSupported()
}

func RevocationSigAlgorithms(c Configuration) []string {
	if !c.RevocationAuthMethodPrivateKeyJWTSupported() {
		return nil
	}
	return c.RevocationEndpointSigningAlgorithmsSupported()
}

func RequestObjectSigAlgorithms(c Configuration) []string {
	if !c.RequestObjectSupported() {
		return nil
	}
	return c.RequestObjectSigningAlgorithmsSupported()
}
