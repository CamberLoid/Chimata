package clientlib

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"

	"github.com/CamberLoid/Chimata/internal/users"
	"github.com/tuneinsight/lattigo/v4/rlwe"
)

// 继承 users.User
type User struct {
	// 集成
	users.User

	// 服务端认证，现阶段不考虑
	OAuth string
}

// ImportCKKSKeychainFromFile 从文件中导入 CKKS 密钥链
// 目前不考虑
func ImportCKKSKeychainFromFile() {
	panic("Not implemented yet!")
}

// --- 签名部分 ---

func (u User) Sign(ct interface{}) (sig []byte, e error) {
	switch ct.(type) {
	case rlwe.Ciphertext:
		return u.SignCipherText(ct.(rlwe.Ciphertext))
	case []byte:
		return signByte(ct.([]byte), u.UserECDSAKeyChain[0].ECDSAPrivateKey)
	default:
		return nil, errors.New("unknown type. Accept rlwe.Ciphertext or []byte only.")
	}
}

// SignAcceptTransactionCT() 对接受交易的密文进行签名
// 接收方式为对 "Accept+"+CT 进行签名
func (u User) SignAcceptTransactionCT(ct rlwe.Ciphertext) (sig []byte, e error) {
	// 检查是否可以签名
	if e = u.checkSignAvailability(); e != nil {
		return nil, e
	}

	acceptCT, e := ct.MarshalBinary()
	if e != nil {
		return nil, e
	}

	acceptCT = append([]byte("Accept+"), acceptCT...)

	sig, e = signByte(acceptCT, u.UserECDSAKeyChain[0].ECDSAPrivateKey)
	return
}

// 对密文进行签名
func (u User) SignCipherText(ct rlwe.Ciphertext) (sig []byte, e error) {
	// 检查是否可以签名
	if e = u.checkSignAvailability(); e != nil {
		return nil, e
	}

	msg, err := ct.MarshalBinary()

	if err != nil {
		panic(err)
	}

	sig, e = signByte(msg, u.UserECDSAKeyChain[0].ECDSAPrivateKey)
	return
}

// signByte() 是一个 Low-level 签名方法
func signByte(msg []byte, key *ecdsa.PrivateKey) (sig []byte, e error) {
	hash := sha256.Sum256(msg)
	sig, e = ecdsa.SignASN1(rand.Reader, key, hash[:])

	return
}

// checkSignAvailability() 检查是否可以签名
func (u User) checkSignAvailability() (e error) {
	if u.UserECDSAKeyChain == nil {
		return errors.New("No ECDSA KeyChain found!")
	}

	if u.UserECDSAKeyChain[0].ECDSAPrivateKey == nil {
		return errors.New("No ECDSA Private Key found!")
	}
	return nil
}

// VerifyCTSignature 以密文对象为输入，验证签名
func (u User) VerifyCTSignature(ct *rlwe.Ciphertext, sig []byte) (bool, error) {
	if ct == nil {
		return false, fmt.Errorf("no ciphertext found")
	}
	ctBytes, err := ct.MarshalBinary()
	if err != nil {
		return false, err
	}
	return u.VerifySignature(ctBytes, sig)
}

// Low-level 验证签名方法
func (u User) VerifySignature(payload []byte, sig []byte) (bool, error) {
	hash := sha256.Sum256(payload)
	return ecdsa.VerifyASN1(u.UserECDSAKeyChain[0].ECDSAPublicKey, hash[:], sig), nil
}

// --- 解密部分 ---

func (u User) DecryptAmountFromCT(ct *rlwe.Ciphertext) (amount float64, err error) {
	if u.UserCKKSKeyChain == nil {
		return 0, errors.New("No CKKS KeyChain found!")
	}
	if u.UserCKKSKeyChain[0].CKKSPrivateKey == nil {
		return 0, errors.New("No CKKS Private Key found!")
	}

	return CKKSDecryptAmountFromCT(ct, u.UserCKKSKeyChain[0].CKKSPrivateKey), nil
}

func (u User) GetBalance() (balance float64, err error) {
	b, err := ServerGetBalance(DefaultServerURL, u.UserIdentifier)
	if err != nil {
		panic(err)
	}

	return u.DecryptAmountFromCT(b)
}
