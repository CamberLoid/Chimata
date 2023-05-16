package clientlib_test

import (
	"fmt"
	"math"
	"testing"

	"github.com/CamberLoid/Chimata/internal/clientlib"
	"github.com/CamberLoid/Chimata/internal/misc"
	"github.com/tuneinsight/lattigo/v4/ckks"
	"github.com/tuneinsight/lattigo/v4/rlwe"
)

func TestCKKSEncryptAndDecrypt(t *testing.T) {
	params, _ := ckks.NewParametersFromLiteral(ckks.PN12QP109)
	keyGen := ckks.NewKeyGenerator(params)
	sk, pk := keyGen.GenKeyPair()
	if res, err := testCKKSEncryptAndDecrypt(sk, pk); !res {
		t.Error(err)
	}
}

func BenchmarkCKKSEncryptAndDecrypt(b *testing.B) {
	params, _ := ckks.NewParametersFromLiteral(ckks.PN12QP109)
	keyGen := ckks.NewKeyGenerator(params)
	sk, pk := keyGen.GenKeyPair()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if res, err := testCKKSEncryptAndDecrypt(sk, pk); !res {
			b.Error(err)
		}
	}
}

func testCKKSEncryptAndDecrypt(sk *rlwe.SecretKey, pk *rlwe.PublicKey) (bool, error) {
	// 创建一个随机浮点数
	randFloat := misc.GenRandFloat()

	ct := clientlib.CKKSEncryptAmount(randFloat, pk)
	decrypted := clientlib.CKKSDecryptAmountFromCT(ct, sk)

	if math.Abs(decrypted-randFloat) > 0.01 {
		return false, fmt.Errorf("decrypted amount is not equal to the original amount, got %f, expected %f", decrypted, randFloat)
	}

	return true, fmt.Errorf("test success, got %f, expected %f", decrypted, randFloat)
}
