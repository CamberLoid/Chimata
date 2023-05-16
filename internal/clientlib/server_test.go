package clientlib_test

import (
	"fmt"
	"math"
	"net/http"
	"testing"

	"github.com/CamberLoid/Chimata/internal/clientlib"
	"github.com/CamberLoid/Chimata/internal/misc"
	"github.com/tuneinsight/lattigo/v4/ckks"
	"github.com/tuneinsight/lattigo/v4/rlwe"
)

func checkServerAvailabilities() bool {
	resp, err := http.Get("http://127.0.0.1:16001/version")
	if err != nil {
		return false
	}
	return resp.Status == "200 OK"
}

func testCreateTransferJobBySenderPK() error {
	var err error

	tx, err := userSender.TransferBySenderPK(&userReceipt, misc.GenRandFloat())
	if err != nil {
		return err
	}
	_, err = userSender.CreateTransferJob(tx)
	if err != nil {
		return err
	}
	return nil
}

func testCreateTransferJobByReceiptPK() error {
	var err error
	var randAmount = misc.GenRandFloat()

	tx, err := userSender.TransferByReceiptPK(&userReceipt, randAmount)
	if err != nil {
		return err
	}

	txNew, err := userSender.CreateTransferJob(tx)
	if err != nil {
		return err
	}

	// Check if amount is correct
	ctSender := new(rlwe.Ciphertext)
	err = ctSender.UnmarshalBinary(txNew.CTSender)
	if err != nil {
		return err
	}
	if newAmount, err := userSender.DecryptAmountFromCT(ctSender); err != nil {
		return err
	} else if math.Abs(newAmount-randAmount) > 0.01 {
		return fmt.Errorf("decrypted amount fail to verify")
	}

	// Accept transaction
	_, err = userReceipt.AcceptTransactionByTransaction(txNew)
	if err != nil {
		return err
	}
	err = userReceipt.CreateConfirmTransactionTask(txNew)
	if err != nil {
		return err
	}

	return nil
}

func TestCreateTransferJobBySenderPK(t *testing.T) {
	if !checkServerAvailabilities() {
		t.Skip("server is not available")
	}
	initTestRandomUser()
	var err error
	if err = testRegisterSwk(); err != nil {
		t.Error(err)
	}
	err = testCreateTransferJobBySenderPK()
	if err != nil {
		t.Error(err)
	}
}

func TestCreateTransferJobByReceiptPK(t *testing.T) {
	if !checkServerAvailabilities() {
		t.Skip("server is not available")
	}
	var err error
	initTestRandomUser()
	if err = testRegisterSwk(); err != nil {
		t.Error(err)
	}
	err = testCreateTransferJobByReceiptPK()
	if err != nil {
		t.Error(err)
	}
}

func testRegisterUser() error {
	initTestRandomUser()
	if err := userSender.RegisterUser(); err != nil {
		return err
	}
	if err := userReceipt.RegisterUser(); err != nil {
		return err
	}
	return nil
}

func TestRegisterUser(t *testing.T) {
	if !checkServerAvailabilities() {
		t.Skip()
	}
	err := testRegisterUser()
	if err != nil {
		t.Error(err)
	}
}

func testRegisterSwk() error {
	var err error
	err = testRegisterUser()
	if err != nil {
		return err
	}

	params := misc.GetCKKSParams()
	keygen := ckks.NewKeyGenerator(params)
	swk1 := keygen.GenSwitchingKey(userSender.UserCKKSKeyChain[0].CKKSPrivateKey,
		userReceipt.UserCKKSKeyChain[0].CKKSPrivateKey)
	err = clientlib.RegisterSwk(userSender.UserIdentifier,
		userReceipt.UserIdentifier,
		swk1)
	if err != nil {
		return err
	}

	swk2 := keygen.GenSwitchingKey(userReceipt.UserCKKSKeyChain[0].CKKSPrivateKey,
		userSender.UserCKKSKeyChain[0].CKKSPrivateKey)
	err = clientlib.RegisterSwk(userReceipt.UserIdentifier,
		userSender.UserIdentifier,
		swk2)
	return err
}

func TestRegisterSwk(t *testing.T) {
	if !checkServerAvailabilities() {
		t.Skip()
	}
	err := testRegisterSwk()
	if err != nil {
		t.Error(err)
	}
}

func BenchmarkRegisterSwk(b *testing.B) {
	if !checkServerAvailabilities() {
		b.Skip()
	}
	for i := 0; i < b.N; i++ {
		if err := testRegisterSwk(); err != nil {
			b.Error(err)
		}
	}
}

func BenchmarkRegisterUser(b *testing.B) {
	if !checkServerAvailabilities() {
		b.Skip()
	}
	for i := 0; i < b.N; i++ {
		if err := testRegisterUser(); err != nil {
			b.Error(err)
		}
	}
}
func BenchmarkCreateTransferJobBySenderPK(b *testing.B) {
	if !checkServerAvailabilities() {
		b.Skip()
	}
	initTestRandomUser()
	var err error
	if err = testRegisterSwk(); err != nil {
		b.Error(err)
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if err = testCreateTransferJobBySenderPK(); err != nil {
			b.Error(err)
		}
	}
}

func BenchmarkCreateTransferJobByReceiptPK(b *testing.B) {
	if !checkServerAvailabilities() {
		b.Skip()
	}
	initTestRandomUser()
	var err error
	if err = testRegisterSwk(); err != nil {
		b.Error(err)
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if err = testCreateTransferJobByReceiptPK(); err != nil {
			b.Error(err)
		}
	}
}
