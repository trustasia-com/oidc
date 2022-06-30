package op

import (
	"context"
	"errors"
	"fmt"

	"gopkg.in/square/go-jose.v2"

	"github.com/zitadel/logging"
)

type Signer interface {
	Health(ctx context.Context) error
	Signer() jose.Signer
	SignatureAlgorithm() jose.SignatureAlgorithm
}

type tokenSigner struct {
	signer  jose.Signer
	storage AuthStorage
	alg     jose.SignatureAlgorithm
}

func NewSigner(storage AuthStorage, key jose.SigningKey) (Signer, error) {
	s := &tokenSigner{
		storage: storage,
	}
	err := s.exchangeSigningKey(key)

	return s, err
}

func (s *tokenSigner) Health(_ context.Context) error {
	if s.signer == nil {
		return errors.New("no signer")
	}
	if string(s.alg) == "" {
		return errors.New("no signing algorithm")
	}
	return nil
}

func (s *tokenSigner) Signer() jose.Signer {
	return s.signer
}

func (s *tokenSigner) refreshSigningKey(ctx context.Context, keyCh <-chan jose.SigningKey) {
	for {
		select {
		case <-ctx.Done():
			return
		case key := <-keyCh:
			s.exchangeSigningKey(key)
		}
	}
}

func (s *tokenSigner) exchangeSigningKey(key jose.SigningKey) error {
	s.alg = key.Algorithm
	if key.Algorithm == "" || key.Key == nil {
		s.signer = nil
		return errors.New("signer has no key")
	}
	var err error
	s.signer, err = jose.NewSigner(key, &jose.SignerOptions{})
	if err != nil {
		logging.New().WithError(err).Error("error creating signer")
		return fmt.Errorf("error creating signer,%s", err.Error())
	}
	return nil
}

func (s *tokenSigner) SignatureAlgorithm() jose.SignatureAlgorithm {
	return s.alg
}
