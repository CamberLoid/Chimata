package misc

import (
	"crypto/rand"
	"math/big"

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

func GetCKKSParams() ckks.Parameters {
	p, _ := ckks.NewParametersFromLiteral(ckks.PN12QP109)
	return p
}

func GenRandFloat() float64 {
	randInt, _ := rand.Int(rand.Reader, big.NewInt(1000000))
	randFloat := float64(randInt.Int64()) / 100.0

	return randFloat
}
