// crypto.go: 密码学相关的函数和结构体

package client_lib

/*  CKKS编解码器初始化
 */

import (
	"crypto/elliptic"

	"github.com/tuneinsight/lattigo/v4/ckks"
	"github.com/tuneinsight/lattigo/v4/rlwe"
)

// CKKS 安全参数和公用结构体
var (
	CKKSEncoder ckks.Encoder
	CKKSParams  ckks.Parameters
	// 方案中使用 P-256 作为曲线参数
	ECDSACurve elliptic.Curve = elliptic.P256()
)

// 对参数等进行初始化
func CryptoInit() (err error) {
	// 参数初始化
	CKKSParams, err = ckks.NewParametersFromLiteral(ckks.PN12QP109)

	if err != nil {
		return
	}

	// 编码器初始化
	CKKSEncoder = ckks.NewEncoder(CKKSParams)

	return
}

// CKKSEncryptAmount 对数字（交易金额）进行基于 CKKS 的加密
// 输入：金额，公钥
// 输出：密文（rlwe.ct）
func CKKSEncryptAmount(amount float64, pk *rlwe.PublicKey) *rlwe.Ciphertext {
	pt := CKKSEncoder.EncodeNew(
		amount,
		CKKSParams.MaxLevel(),
		CKKSParams.DefaultScale(),
		CKKSParams.LogSlots())
	ct := ckks.NewEncryptor(CKKSParams, pk).EncryptNew(pt)

	return ct
}

// CKKSDecryptAmountFromCT 从密文中提取加密的金额
// 输入：密文（ct），私钥
// 输出：金额（float64）
func CKKSDecryptAmountFromCT(ct *rlwe.Ciphertext, sk *rlwe.SecretKey) float64 {
	decryptor := ckks.NewDecryptor(CKKSParams, sk)
	pt := decryptor.DecryptNew(ct)
	amount := CKKSEncoder.Decode(pt, CKKSParams.LogSlots())

	return roundToCent(real(amount[0]))
}
