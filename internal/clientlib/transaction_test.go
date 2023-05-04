package clientlib_test

import (
	"fmt"
	"math"
	"testing"

	"github.com/CamberLoid/Chimata/internal/clientlib"
	"github.com/CamberLoid/Chimata/internal/transaction"
	"github.com/tuneinsight/lattigo/v4/ckks"
	"github.com/tuneinsight/lattigo/v4/rlwe"
)

func checkIfSenderAndReceiptCorrect(t *transaction.Transaction) bool {
	return t.Sender == userSender.UserIdentifier && t.Receipt == userReceipt.UserIdentifier
}

func TestTransferBySenderPK(t *testing.T) {
	err := testTransferBySenderPK()
	if err != nil {
		t.Error(err)
	}
}

func BenchmarkTransferBySenderPK(b *testing.B) {
	for i := 0; i < b.N; i++ {
		if err := testTransferBySenderPK(); err != nil {
			b.Error(err)
		}
	}
}

func testTransferBySenderPK() error {
	initTestRandomUser()
	randFloat := clientlib.GenRandFloat()

	t, err := userSender.TransferBySenderPK(&userReceipt, randFloat)
	if err != nil {
		return err
	}

	// 检查收款方和付款方的信息
	if checkIfSenderAndReceiptCorrect(t) == false {
		return fmt.Errorf("checkIfSenderAndReceiptCorrect failed")
	}

	// 检查密文合法性
	ct, err := t.GetSenderCT()
	if err != nil {
		return err
	}
	decrypted, err := userSender.DecryptAmountFromCT(ct)
	if err != nil {
		return err
	}
	if math.Abs(decrypted-randFloat) > 0.01 {
		return fmt.Errorf("decrypted amount is not equal to the original amount, got %f, expected %f", decrypted, randFloat)
	}

	// 验证签名
	res, err := userSender.VerifySignature(
		t.CTSender,
		t.SigCTSender,
	)
	if err != nil {
		return err
	}
	if !res {
		return fmt.Errorf("func VerifySignature failed")
	}
	return nil
}

func TestTransferByReceiptPK(t *testing.T) {
	err := testTransferByReceiptPK()
	if err != nil {
		t.Error(err)
	}
}

func BenchmarkTransferByReceiptPK(b *testing.B) {
	for i := 0; i < b.N; i++ {
		err := testTransferByReceiptPK()
		if err != nil {
			b.Error(err)
		}
	}
}

func testTransferByReceiptPK() (err error) {
	initTestRandomUser()
	randFloat := clientlib.GenRandFloat()

	t, err := userSender.TransferByReceiptPK(&userReceipt, randFloat)
	if err != nil {
		return err
	}

	// 检查收款方和付款方的信息
	if checkIfSenderAndReceiptCorrect(t) == false {
		return fmt.Errorf("checkIfSenderAndReceiptCorrect failed")
	}

	// 验证签名
	res, err := userSender.VerifySignature(
		t.CTReceipt,
		t.SigCTReceipt,
	)
	if err != nil {
		return err
	}
	if !res {
		return fmt.Errorf("func VerifySignature failed")
	}
	return nil
}

// --- ACCEPT ---

func genUnconfirmedTransaction(amount float64) (tx *transaction.Transaction) {
	//amount := clientlib.GenRandFloat()
	params := clientlib.GetCKKSParams()
	keyGen := ckks.NewKeyGenerator(params)
	evl := ckks.NewEvaluator(params, rlwe.EvaluationKey{})

	swk := keyGen.GenSwitchingKey(
		userReceipt.UserCKKSKeyChain[0].CKKSPrivateKey,
		userSender.UserCKKSKeyChain[0].CKKSPrivateKey,
	)

	tx, _ = userSender.TransferByReceiptPK(&userReceipt, amount)
	ctReceipt, _ := tx.GetReceiptCT()
	ctSender := evl.SwitchKeysNew(ctReceipt, swk)
	tx.CTSender, _ = ctSender.MarshalBinary()

	return
}

func testAcceptTransactionByTransaction() (err error) {
	initTestRandomUser()
	amount := clientlib.GenRandFloat()
	t := genUnconfirmedTransaction(amount)

	// 检查收款方和付款方的信息
	if checkIfSenderAndReceiptCorrect(t) == false {
		return fmt.Errorf("checkIfSenderAndReceiptCorrect failed")
	}

	// 验证签名
	_, err = userReceipt.AcceptTransactionByTransaction(t)
	// 验证密文
	ct, err := t.GetReceiptCT()
	if err != nil {
		return err
	}
	decrypted, err := userReceipt.DecryptAmountFromCT(ct)
	if err != nil {
		return err
	}
	if math.Abs(decrypted-amount) > 0.01 {
		return fmt.Errorf("decrypted amount is not equal to the original amount, got %f, expected %f", decrypted, amount)
	}

	return nil
}

func TestAcceptTransactionByTransaction(t *testing.T) {
	err := testAcceptTransactionByTransaction()
	if err != nil {
		t.Error(err)
	}
}

func BenchmarkAcceptTransactionByTransaction(b *testing.B) {
	for i := 0; i < b.N; i++ {
		if err := testAcceptTransactionByTransaction(); err != nil {
			b.Error(err)
		}
	}
}
