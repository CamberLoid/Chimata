package clientlib_test

import (
	"net/http"
	"testing"

	"github.com/CamberLoid/Chimata/internal/clientlib"
	"github.com/tuneinsight/lattigo/v4/ckks"
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
	initTestRandomUser()
	if err = testRegisterSwk(); err != nil {
		return err
	}

	tx, err := userSender.TransferBySenderPK(&userReceipt, clientlib.GenRandFloat())
	if err != nil {
		return err
	}
	_, err = userSender.CreateTransferJob(tx)
	if err != nil {
		return err
	}
	return nil
}

func TestCreateTransferJob(t *testing.T) {
	if !checkServerAvailabilities() {
		t.Skip("server is not available")
	}
	err := testCreateTransferJobBySenderPK()
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

	params := clientlib.GetCKKSParams()
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
	err = clientlib.RegisterSwk(userSender.UserIdentifier,
		userReceipt.UserIdentifier,
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
