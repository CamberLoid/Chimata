package serverlib_test

import (
	"math"
	"testing"

	"github.com/CamberLoid/Chimata/internal/clientlib"
	"github.com/CamberLoid/Chimata/internal/misc"
	"github.com/CamberLoid/Chimata/internal/serverlib"
	"github.com/tuneinsight/lattigo/v4/ckks"
	"github.com/tuneinsight/lattigo/v4/rlwe"
)

func BenchmarkReEncryptCTWithSwk(B *testing.B) {
	var (
		ctIn, ctOut *rlwe.Ciphertext
		res         float64
		err         error
	)
	keyGen := ckks.NewKeyGenerator(misc.GetCKKSParams())
	sk1, pk := keyGen.GenKeyPair()
	sk2 := keyGen.GenSecretKey()
	swk := keyGen.GenSwitchingKey(sk1, sk2)
	for i := 0; i < B.N; i++ {
		B.StopTimer()
		randAmount := clientlib.GenRandFloat()
		ctIn = clientlib.CKKSEncryptAmount(randAmount, pk)
		B.StartTimer()
		ctOut, err = serverlib.ReEncryptCTWithSwk(ctIn, swk)
		B.StopTimer()
		if err != nil {
			B.Fail()
			continue
		}
		res = clientlib.CKKSDecryptAmountFromCT(ctOut, sk2)
		if math.Abs(res-randAmount) > 0.01 {
			B.Errorf("decrypted amount is not equal to the original amount, got %f, expected %f", res, randAmount)
			continue
		}
	}
}
