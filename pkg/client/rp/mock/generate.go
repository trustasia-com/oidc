package mock

//go:generate mockgen -package mock -destination ./verifier.mock.go github.com/trustasia-com/oidc/pkg/rp Verifier
