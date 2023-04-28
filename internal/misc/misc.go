package misc

import (
	"github.com/tuneinsight/lattigo/v4/ckks"
	"github.com/tuneinsight/lattigo/v4/rlwe"
)

func GenerateSwitchingKey(skIn, skOut *rlwe.SecretKey) *rlwe.SwitchingKey {
	params, _ := ckks.NewParametersFromLiteral(ckks.PN12QP109)
	keyGenerator := ckks.NewKeyGenerator(params)

	return keyGenerator.GenSwitchingKey(skIn, skOut)
}

// NewCiphertext 创建新的密文
func NewCiphertext() *rlwe.Ciphertext {
	params, _ := ckks.NewParametersFromLiteral(ckks.PN12QP109)
	ct := ckks.NewCiphertext(params, 1, params.MaxLevel())
	return ct
}
