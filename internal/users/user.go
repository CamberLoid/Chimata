// 包 users 包含了用户的相关接口、结构体和方法
package users

import (
	"crypto/ecdsa"

	"github.com/CamberLoid/Chimata/internal/key"
	"github.com/google/uuid"
	"github.com/tuneinsight/lattigo/v4/ckks"
	"github.com/tuneinsight/lattigo/v4/rlwe"
)

// 方案中的用户，包含了用户的标识符、CKKS 密钥链和 ECDSA 密钥链
// 因为一个用户可能存在多个密钥对，所以使用 Slice 来存储
// 新增：为实现简便，约定一个用户只有一对 CKKS 和 Elliptic 密钥
type User struct {
	UserIdentifier    uuid.UUID // 或者是 [16]bytes
	UserName          string
	UserCKKSKeyChain  []key.CKKSKeyChain
	UserECDSAKeyChain []key.ECDSAKeyChain
}

var (
	// 预设的 CKKS 安全参数
	ckksParams, _ = ckks.NewParametersFromLiteral(ckks.PN12QP109)
)

// 生成一个新的空值用户
func NewUser() *User {
	user := new(User)
	user.UserIdentifier = uuid.New()
	return user
}

// 生成一个新的用户，包含用户名
func NewUserWithUserName(userName string) *User {
	user := NewUser()
	user.UserName = userName
	return user
}

// ImportWithCKKS{Secret, Public}Key9
// 方法用于向 User 类型导入 CKKS 密钥对
func (user *User) ImportWithCKKSSecretKey(sk *rlwe.SecretKey) error {
	keyGenerator := ckks.NewKeyGenerator(ckksParams)
	pk := keyGenerator.GenPublicKey(sk)
	user.UserCKKSKeyChain = append(user.UserCKKSKeyChain, key.CKKSKeyChain{CKKSPrivateKey: sk, CKKSPublicKey: pk})
	return nil
}

func (user *User) ImportWithCKKSPublicKey(pk *rlwe.PublicKey) error {
	user.UserCKKSKeyChain = append(user.UserCKKSKeyChain, key.CKKSKeyChain{CKKSPublicKey: pk, CKKSPrivateKey: nil})
	return nil
}

func (user *User) ImportECDSAPublicKey(pk *ecdsa.PublicKey) error {
	user.UserECDSAKeyChain = append(user.UserECDSAKeyChain, key.ECDSAKeyChain{ECDSAPublicKey: pk, ECDSAPrivateKey: nil})
	return nil
}

func (user *User) ImportECDSAPrivateKey(sk *ecdsa.PrivateKey) error {
	pk := sk.PublicKey
	user.UserECDSAKeyChain = append(user.UserECDSAKeyChain, key.ECDSAKeyChain{ECDSAPrivateKey: sk, ECDSAPublicKey: &pk})
	return nil
}
