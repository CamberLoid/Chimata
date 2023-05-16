package serverlib_test

import (
	"fmt"
	"math"
	"testing"

	"github.com/CamberLoid/Chimata/internal/clientlib"
	"github.com/CamberLoid/Chimata/internal/misc"
	"github.com/CamberLoid/Chimata/internal/serverlib"
	"github.com/CamberLoid/Chimata/internal/transaction"
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
		randAmount := misc.GenRandFloat()
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

// 密文同态更新

func testGetUpdatedSenderBalance(
	tx *transaction.Transaction,
	balanceCT *rlwe.Ciphertext,
	balancePT, amount float64,
	sk *rlwe.SecretKey,
	isTest bool,
) (err error) {
	updated, err := serverlib.GetUpdatedSenderBalance(tx, balanceCT)
	if err != nil {
		return err
	}

	if isTest {
		updatedPT := clientlib.CKKSDecryptAmountFromCT(updated, sk)
		if math.Abs((balancePT-amount)-updatedPT) < 0.01 {
			return nil
		} else {
			return fmt.Errorf("validation failed: got %v, expected %v", updatedPT, balancePT-amount)
		}
	} else {
		return nil
	}
}

func TestGetUpdatedSenderBalance(t *testing.T) {
	var err error
	tx := new(transaction.Transaction)
	keyGen := ckks.NewKeyGenerator(misc.GetCKKSParams())
	sk, pk := keyGen.GenKeyPair()
	randBalance := misc.GenRandFloat()
	randAmount := misc.GenRandFloat()
	BalanceCT := clientlib.CKKSEncryptAmount(randBalance, pk)
	AmountCT := clientlib.CKKSEncryptAmount(randAmount, pk)

	tx.CTSender, err = AmountCT.MarshalBinary()
	if err != nil {
		t.Error(err)
	}

	//tx.CTReceipt = tx.CTSender

	if err = testGetUpdatedSenderBalance(
		tx, BalanceCT, randBalance, randAmount, sk,
		true); err != nil {
		t.Error(err)
	}
}

func BenchmarkGetUpdatedSenderBalance(b *testing.B) {
	var err error
	tx := new(transaction.Transaction)
	keyGen := ckks.NewKeyGenerator(misc.GetCKKSParams())
	sk, pk := keyGen.GenKeyPair()
	randBalance := misc.GenRandFloat()
	randAmount := misc.GenRandFloat()
	BalanceCT := clientlib.CKKSEncryptAmount(randBalance, pk)
	AmountCT := clientlib.CKKSEncryptAmount(randAmount, pk)

	tx.CTSender, err = AmountCT.MarshalBinary()
	if err != nil {
		b.Error(err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if err = testGetUpdatedSenderBalance(
			tx, BalanceCT, randBalance, randAmount,
			sk, false); err != nil {
			b.Error(err)
		}
	}
}

func testGetUpdatedReceiptBalance(
	tx *transaction.Transaction,
	balanceCT *rlwe.Ciphertext,
	balancePT, amount float64,
	sk *rlwe.SecretKey,
	isTest bool,
) (err error) {
	updated, err := serverlib.GetUpdatedReceiptBalance(tx, balanceCT)
	if err != nil {
		return err
	}

	if isTest {
		updatedPT := clientlib.CKKSDecryptAmountFromCT(updated, sk)
		if math.Abs((balancePT+amount)-updatedPT) < 0.01 {
			return nil
		} else {
			return fmt.Errorf("validation failed: got %v, expected %v", updatedPT, balancePT-amount)
		}
	} else {
		return nil
	}
}

func TestGetUpdatedReceiptBalance(t *testing.T) {
	var err error
	tx := new(transaction.Transaction)
	keyGen := ckks.NewKeyGenerator(misc.GetCKKSParams())
	sk, pk := keyGen.GenKeyPair()
	randBalance := misc.GenRandFloat()
	randAmount := misc.GenRandFloat()
	BalanceCT := clientlib.CKKSEncryptAmount(randBalance, pk)
	AmountCT := clientlib.CKKSEncryptAmount(randAmount, pk)

	tx.CTReceipt, err = AmountCT.MarshalBinary()
	if err != nil {
		t.Error(err)
	}

	if err = testGetUpdatedReceiptBalance(
		tx, BalanceCT, randBalance, randAmount, sk,
		true); err != nil {
		t.Error(err)
	}
}

func BenchmarkGetUpdatedReceiptBalance(b *testing.B) {
	var err error
	tx := new(transaction.Transaction)
	keyGen := ckks.NewKeyGenerator(misc.GetCKKSParams())
	sk, pk := keyGen.GenKeyPair()
	randBalance := misc.GenRandFloat()
	randAmount := misc.GenRandFloat()
	BalanceCT := clientlib.CKKSEncryptAmount(randBalance, pk)
	AmountCT := clientlib.CKKSEncryptAmount(randAmount, pk)

	tx.CTReceipt, err = AmountCT.MarshalBinary()
	if err != nil {
		b.Error(err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if err = testGetUpdatedReceiptBalance(
			tx, BalanceCT, randBalance, randAmount,
			sk, false); err != nil {
			b.Error(err)
		}
	}
}

func BenchmarkGetUpdatedBalance(b *testing.B) {
	var err error
	tx := new(transaction.Transaction)
	keyGen := ckks.NewKeyGenerator(misc.GetCKKSParams())
	_, pk_S := keyGen.GenKeyPair()
	_, pk_R := keyGen.GenKeyPair()
	randBalance_S := misc.GenRandFloat()
	randBalance_R := misc.GenRandFloat()
	randAmount := misc.GenRandFloat()
	BalanceCT_S := clientlib.CKKSEncryptAmount(randBalance_S, pk_S)
	BalanceCT_R := clientlib.CKKSEncryptAmount(randBalance_R, pk_R)
	AmountCT_S := clientlib.CKKSEncryptAmount(randAmount, pk_S)
	AmountCT_R := clientlib.CKKSEncryptAmount(randAmount, pk_R)

	if tx.CTReceipt, err = AmountCT_R.MarshalBinary(); err != nil {
		b.Error(err)
	}
	if tx.CTSender, err = AmountCT_S.MarshalBinary(); err != nil {
		b.Error(err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, _, err = serverlib.GetUpdatedBalance(
			tx, BalanceCT_S, BalanceCT_R,
		); err != nil {
			b.Error(err)
		}
	}
}
