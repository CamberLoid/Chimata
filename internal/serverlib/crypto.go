package serverlib

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"fmt"
	"reflect"

	"github.com/tuneinsight/lattigo/v4/ckks"
	"github.com/tuneinsight/lattigo/v4/rlwe"
)

// --- 代理重加密部分 ---

func ReEncryptCTWithSwk(ctIn *rlwe.Ciphertext, swk *rlwe.SwitchingKey) (ctOut *rlwe.Ciphertext, err error) {
	params, _ := ckks.NewParametersFromLiteral(ckks.PN12QP109)
	evaluator := ckks.NewEvaluator(params, rlwe.EvaluationKey{})

	// 处理接下来可能出现的 panic
	defer func() {
		if p := recover(); p != nil {
			ctOut = nil
			err = fmt.Errorf("re-encrypt failed, got panic: %v", p)
		}
	}()

	ctOut = evaluator.SwitchKeysNew(ctIn, swk)
	return
}

// --- 签名部分 ---

// ValidateSignatureForCipherText
// 输入公钥和密文和签名
// 输出验证结果
func ValidateSignatureForCipherText(ct interface{}, sig []byte, pk *ecdsa.PublicKey) (isValid bool, err error) {
	var _ct *rlwe.Ciphertext
	var msg []byte
	switch v := ct.(type) {
	case *rlwe.Ciphertext:
		_ct = v
		msg, err = _ct.MarshalBinary()
		if err != nil {
			return false, err
		}
	case []byte:
		msg = v
		err = _ct.UnmarshalBinary(msg)
		if err != nil {
			return false, err
		}
	default:
		return false, fmt.Errorf("invalid type of _ct, accept *rlwe.Ciphertext or []byte, received " + reflect.TypeOf(_ct).String())
	}
	return ValidateSignatureBase(msg, sig, pk), nil
}

// ValidateSignatureForAcceptCipherText
// 输入公钥和密文和签名
// 输出验证结果
func ValidateSignatureForAcceptCipherText(ct interface{}, sig []byte, pk *ecdsa.PublicKey) (isValid bool, err error) {
	var _ct *rlwe.Ciphertext
	var msg []byte
	switch v := ct.(type) {
	case *rlwe.Ciphertext:
		_ct = v
		msg, err = _ct.MarshalBinary()
		if err != nil {
			return false, err
		}
	case []byte:
		msg = v
		err = _ct.UnmarshalBinary(msg)
		if err != nil {
			return false, err
		}
	default:
		return false, fmt.Errorf("invalid type of _ct, accept *rlwe.Ciphertext or []byte, received " + reflect.TypeOf(ct).String())
	}

	msg = []byte("ACCEPT" + string(msg))

	return ValidateSignatureBase(msg, sig, pk), nil
}

func ValidateSignatureBase(msg []byte, sig []byte, pk *ecdsa.PublicKey) (isValid bool) {
	hash := sha256.Sum256(msg)
	return ecdsa.VerifyASN1(pk, hash[:], sig)
}

// --- 密文更新部分 ---

// GetUpdatedSenderBalance 计算新的发送方余额，也就是包装过的密文减法
// 输入原余额和变动金额，输出新的余额
func GetUpdatedSenderBalance(balance, txAmount *rlwe.Ciphertext) (updated *rlwe.Ciphertext, err error) {
	defer func() {
		if p := recover(); p != nil {
			updated = nil
			err = fmt.Errorf("adding failed %v", p)
		}
	}()

	evaluator := NewEmptyEvaluator()
	updated = evaluator.AddNew(balance, evaluator.MultByConstNew(txAmount, -1))
	return
}

// GetUpdatedReceiptBalance 计算新的接收方余额，也就是包装过的密文加法
// 输入原余额和变动金额，输出新的余额
func GetUpdatedReceiptBalance(balance, txAmount *rlwe.Ciphertext) (updated *rlwe.Ciphertext, err error) {
	defer func() {
		if p := recover(); p != nil {
			updated = nil
			err = fmt.Errorf("calculating ciphertext failed: %v", p)
		}
	}()

	evaluator := NewEmptyEvaluator()
	updated = evaluator.AddNew(balance, txAmount)
	return
}

// NewCiphertext 创建新的密文
func NewCiphertext() *rlwe.Ciphertext {
	params, _ := ckks.NewParametersFromLiteral(ckks.PN12QP109)
	ct := ckks.NewCiphertext(params, 1, params.MaxLevel())
	return ct
}

func NewEmptyEvaluator() ckks.Evaluator {
	params, _ := ckks.NewParametersFromLiteral(ckks.PN12QP109)
	evl := ckks.NewEvaluator(params, rlwe.EvaluationKey{})
	return evl
}