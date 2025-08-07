package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"

	"github.com/lestrrat-go/jwx/jwa"
	"github.com/lestrrat-go/jwx/jwk"
)

type mockJwkAutoRefresh struct {
	keySet     jwk.Set
	privateSet jwk.Set
}

func (m *mockJwkAutoRefresh) PrivateSet() jwk.Set {
	return m.privateSet
}

// implement JwkAutoRefresh
func (m *mockJwkAutoRefresh) Configure(url string, options ...jwk.AutoRefreshOption) {
}

func (m *mockJwkAutoRefresh) Fetch(ctx context.Context, url string) (jwk.Set, error) {
	return m.keySet, nil
}

func (m *mockJwkAutoRefresh) Refresh(ctx context.Context, url string) (jwk.Set, error) {
	return m.keySet, nil
}

func (m *mockJwkAutoRefresh) ErrorSink(ch chan jwk.AutoRefreshError) {
}

func NewMockJwkAutoRefresh() *mockJwkAutoRefresh {
	raw, _ := rsa.GenerateKey(rand.Reader, 2048)

	key, _ := jwk.New(raw)

	var use = jwk.ForSignature

	key.Set(jwk.KeyIDKey, use.String())
	key.Set(jwk.KeyUsageKey, use)

	if use == jwk.ForSignature {
		key.Set(jwk.AlgorithmKey, jwa.RS512)
	} else {
		key.Set(jwk.AlgorithmKey, jwa.RSA1_5)
	}

	privateSet := jwk.NewSet()
	privateSet.Add(key)

	pub, _ := key.PublicKey()

	pub.Set(jwk.KeyIDKey, use.String())

	keySet := jwk.NewSet()
	keySet.Add(pub)
	keysLoaded.Store(true)

	return &mockJwkAutoRefresh{
		keySet:     keySet,
		privateSet: privateSet,
	}
}
