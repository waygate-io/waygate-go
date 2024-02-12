package josencillo

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jwt"
)

type JOSE struct {
	privateKeyset jwk.Set
	publicKeyset  jwk.Set
}

func NewJOSE() (*JOSE, error) {
	j := &JOSE{
		privateKeyset: jwk.NewSet(),
	}

	key, err := GenerateJWK()
	if err != nil {
		return nil, err
	}

	j.privateKeyset.AddKey(key)

	publicKeyset, err := jwk.PublicSetOf(j.privateKeyset)
	if err != nil {
		return nil, err
	}

	j.publicKeyset = publicKeyset

	return j, nil
}

func (j *JOSE) NewJWTBuilder() *JWTBuilder {
	return &JWTBuilder{
		jose: j,
	}
}

type JWT string

func (j *JOSE) NewJWT(claims map[string]interface{}) (string, error) {

	builder := jwt.NewBuilder()

	for key, val := range claims {
		builder.Claim(key, val)
	}

	jwt_, err := builder.Build()
	if err != nil {
		return "", err
	}

	key, exists := j.privateKeyset.Key(0)
	if !exists {
		return "", errors.New("No key available")
	}

	signedJwt, err := jwt.Sign(jwt_, jwt.WithKey(jwa.RS256, key))
	if err != nil {
		return "", err
	}

	return string(signedJwt), nil
}

func (j *JOSE) ParseJWT(jwt_ string) (claims map[string]interface{}, err error) {

	parsed, err := jwt.Parse([]byte(jwt_), jwt.WithKeySet(j.publicKeyset))
	if err != nil {
		return nil, err
	}

	m, err := parsed.AsMap(context.Background())
	if err != nil {
		return nil, err
	}
	printJson(m)

	claims = make(map[string]interface{})

	for k, v := range m {
		claims[k] = v
	}

	return claims, nil
}

type JWTBuilder struct {
	jose   *JOSE
	claims map[string]interface{}
}

func (b *JWTBuilder) Claim(key, val string) *JWTBuilder {
	b.claims[key] = val
	return b
}

func (b *JWTBuilder) Build() (JWT, error) {

	issuedAt := time.Now().UTC()

	builder := jwt.NewBuilder().
		IssuedAt(issuedAt)

	for key, val := range b.claims {
		builder.Claim(key, val)
	}

	_, err := builder.Build()
	if err != nil {
		return "", err
	}

	return "", nil
}

func GenerateJWK() (jwk.Key, error) {
	raw, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}

	key, err := jwk.FromRaw(raw)
	if err != nil {
		return nil, err
	}

	if _, ok := key.(jwk.RSAPrivateKey); !ok {
		return nil, err
	}

	err = jwk.AssignKeyID(key)
	if err != nil {
		return nil, err
	}

	key.Set("alg", "RS256")

	//key.Set(jwk.KeyUsageKey, "sig")
	//keyset := jwk.NewSet()
	//keyset.Add(key)
	//return keyset, nil

	return key, nil
}

func printJson(data interface{}) {
	d, _ := json.MarshalIndent(data, "", "  ")
	fmt.Println(string(d))
}
