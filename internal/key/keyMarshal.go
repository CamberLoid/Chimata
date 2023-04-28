package key

import (
	"crypto/ecdsa"
	"crypto/x509"
	"fmt"

	"github.com/tuneinsight/lattigo/v4/ckks"
	"github.com/tuneinsight/lattigo/v4/rlwe"
)

type CKKSPayload interface {
	MarshalBinary() ([]byte, error)
	UnmarshalBinary([]byte) error
}

func MarshalECDSAPublicKey(pk *ecdsa.PublicKey) []byte {
	data, _ := x509.MarshalPKIXPublicKey(pk)
	return data
}

func UnmarshalECDSAPublicKey(data []byte) (pk *ecdsa.PublicKey, err error) {
	_pubkey, err := x509.ParsePKIXPublicKey(data)
	if err != nil {
		return
	}
	switch v := _pubkey.(type) {
	case *ecdsa.PublicKey:
		return _pubkey.(*ecdsa.PublicKey), nil
	default:
		return nil, fmt.Errorf("not a ecdsa public key, got %v", v)
	}
}

func MarshalCKKSPayload(pk CKKSPayload) []byte {
	data, _ := pk.MarshalBinary()
	return data
}

func UnmarshalCKKSPublicKey(data []byte) (pk *rlwe.PublicKey, err error) {
	err = pk.UnmarshalBinary(data)
	return
}

func UnmarshalCKKSCipherText(data []byte) (ct *rlwe.Ciphertext, err error) {
	ct = ckks.NewCiphertext(
		params, 1, params.MaxLevel(),
	)
	err = ct.UnmarshalBinary(data)
	return
}
