package clientlib_test

import (
	"fmt"
	"math"
	"testing"

	"github.com/CamberLoid/Chimata/internal/clientlib"
	"github.com/tuneinsight/lattigo/v4/ckks"
)

func TestCKKSEncryptAndDecrypt(t *testing.T) {
	if res, err := testCKKSEncryptAndDecrypt(); !res {
		t.Error(err)
	}
}

func BenchmarkCKKSEncryptAndDecrypt(b *testing.B) {
	for i := 0; i < b.N; i++ {
		if res, err := testCKKSEncryptAndDecrypt(); !res {
			b.Error(err)
		} else {
			b.Log(err)
		}
	}
}

func testCKKSEncryptAndDecrypt() (bool, error) {
	// 创建一个随机浮点数
	randFloat := clientlib.GenRandFloat()
	params, _ := ckks.NewParametersFromLiteral(ckks.PN12QP109)
	keyGen := ckks.NewKeyGenerator(params)
	sk, pk := keyGen.GenKeyPair()

	ct := clientlib.CKKSEncryptAmount(randFloat, pk)
	decrypted := clientlib.CKKSDecryptAmountFromCT(ct, sk)

	if math.Abs(decrypted-randFloat) > 0.01 {
		return false, fmt.Errorf("decrypted amount is not equal to the original amount, got %f, expected %f", decrypted, randFloat)
	}

	return true, fmt.Errorf("test success, got %f, expected %f", decrypted, randFloat)
}
