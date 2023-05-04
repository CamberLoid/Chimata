package clientlib_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"fmt"
	"math"
	"testing"

	"github.com/CamberLoid/Chimata/internal/clientlib"
	"github.com/CamberLoid/Chimata/internal/key"
	"github.com/CamberLoid/Chimata/internal/transaction"
	"github.com/CamberLoid/Chimata/internal/users"
	"github.com/google/uuid"
	"github.com/tuneinsight/lattigo/v4/ckks"
)

var (
	userSender  clientlib.User
	userReceipt clientlib.User
)

func makeNewUser(name string) (user clientlib.User) {
	params, _ := ckks.NewParametersFromLiteral(ckks.PN12QP109)
	keygen := ckks.NewKeyGenerator(params)
	user = clientlib.User{
		*users.NewUser(),
		"",
	}
	userCKKSKeyChain := new(key.CKKSKeyChain)
	userCKKSKeyChain.Identifier = uuid.New()
	userCKKSKeyChain.CKKSPrivateKey = keygen.GenSecretKey()
	userCKKSKeyChain.CKKSPublicKey = keygen.GenPublicKey(userCKKSKeyChain.CKKSPrivateKey)
	user.UserCKKSKeyChain = append(userSender.UserCKKSKeyChain, *userCKKSKeyChain)

	userECDSAKeyChain := new(key.ECDSAKeyChain)
	userECDSAKeyChain.Identifier = uuid.New()
	userECDSAKeyChain.ECDSAPrivateKey, _ = ecdsa.GenerateKey(elliptic.P224(), rand.Reader)
	userECDSAKeyChain.ECDSAPublicKey = &userECDSAKeyChain.ECDSAPrivateKey.PublicKey
	user.UserECDSAKeyChain = append(user.UserECDSAKeyChain, *userECDSAKeyChain)

	user.UserName = name

	return
}

func initTransactionTest() {
	userSender = makeNewUser("Alice")
	userReceipt = makeNewUser("Bob")

}

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
	initTransactionTest()
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
	initTransactionTest()
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

func genUnconfirmedTransaction() (tx *transaction.Transaction) {
	amount := clientlib.GenRandFloat()
	params := clientlib.Ge
	tx, _ = userSender.TransferByReceiptPK(&userReceipt, amount)

}

func testAcceptTransactionByTransaction() (err error) {
	//initTransactionTest()
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

	// 验证密文
	ct, err := t.GetReceiptCT()
	if err != nil {
		return err
	}
	decrypted, err := userReceipt.DecryptAmountFromCT(ct)
	if err != nil {
		return err
	}
	if math.Abs(decrypted-randFloat) > 0.01 {
		return fmt.Errorf("decrypted amount is not equal to the original amount, got %f, expected %f", decrypted, randFloat)
	}

	return nil
}
