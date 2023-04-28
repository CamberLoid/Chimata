//lint:ignore U1000 Ignore unused function temporarily for debugging

// 包 Key 包含了方案中可能用到的各种密码学密钥的生成等
package key

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"

	"github.com/google/uuid"
	"github.com/tuneinsight/lattigo/v4/ckks"
	"github.com/tuneinsight/lattigo/v4/rlwe"
)

var (
	// 预设的 CKKS 安全参数
	params, _ = ckks.NewParametersFromLiteral(ckks.PN12QP109)
)

type CKKSKeyChain struct {
	Identifier     uuid.UUID
	CKKSPrivateKey *rlwe.SecretKey
	CKKSPublicKey  *rlwe.PublicKey
}

type ECDSAKeyChain struct {
	Identifier      uuid.UUID
	ECDSAPrivateKey *ecdsa.PrivateKey
	ECDSAPublicKey  *ecdsa.PublicKey
}

type KeyChain struct {
	CKKSKeyChain  CKKSKeyChain
	ECDSAKeyChain ECDSAKeyChain
}

type UserKeyGenerator interface {
	GenerateUserCKKSKey()
	GenerateUserECDSAKey()
}

// Generate a key pair for ECDSA and CKKS Scheme
// Returns
func genKey() {
	panic("Not implemented yet!")
}

// Generate a key pair for transaction signing
func genKeySign() (ecdsa.PrivateKey, ecdsa.PublicKey) {
	sk, _ := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	pk := sk.PublicKey
	return *sk, pk
}

func genKeyCKKS() (*rlwe.PublicKey, *rlwe.SecretKey) {

	ckksKeyGenerator := ckks.NewKeyGenerator(params)
	sk, pk := ckksKeyGenerator.GenKeyPair()

	return pk, sk
}

// TO-DO: 从本地文件中读取 CKKS 密钥
// Consider rlwe.marshal
func importKeyCKKS() {
	panic("Not implemented yet!")

}
