package main

import (
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/CamberLoid/Chimata/internal/db"
	"github.com/CamberLoid/Chimata/internal/key"
	"github.com/CamberLoid/Chimata/internal/restfulpayload"
	"github.com/CamberLoid/Chimata/internal/serverlib"
	"github.com/CamberLoid/Chimata/internal/transaction"
	"github.com/CamberLoid/Chimata/internal/users"
	"github.com/google/uuid"
	"github.com/tuneinsight/lattigo/v4/ckks"
	"github.com/tuneinsight/lattigo/v4/rlwe"
)

// 还没实现的功能的处理函数
func todo(w http.ResponseWriter, req *http.Request) {
	returnFailure(w, req, fmt.Errorf("function not implemented yet"), http.StatusInternalServerError)
}

func HandleNotFound(w http.ResponseWriter, req *http.Request) {
	returnFailure(w, req, fmt.Errorf("function not found: "+req.RequestURI), 404)
}

// Generic failure
func returnFailure(w http.ResponseWriter, req *http.Request, err error, statusCode int) {
	resp := make(map[string]interface{})
	resp["status"] = "failed"
	resp["err"] = err.Error()

	respJSON, _ := json.Marshal(resp)

	w.WriteHeader(statusCode)
	w.Write(respJSON)
	ErrorLogger.Println("Error: " + err.Error())
}

// Handle /version request
func HandlerVersion(w http.ResponseWriter, req *http.Request) {
	respJSON := make(map[string]interface{})
	respJSON["status"] = "OK"
	respJSON["version"] = "0.0.9999"

	respByte, _ := json.Marshal(respJSON)

	w.Write(respByte)
}

// Handle /transaction/create/bySenderPK request
func HandlerTransactionCreateBySenderPK(w http.ResponseWriter, req *http.Request) {
	InfoLogger.Print("New incoming /transaction/create/bySenderPK request")
	var err error
	//tx := new(transaction.Transaction)
	txj := new(transaction.TransactionJSON)

	// 解码
	if err = json.NewDecoder(req.Body).Decode(txj); err != nil {
		returnFailure(w, req, err, http.StatusBadRequest)
		return
	}
	tx, err := txj.CopyToStruct()
	if err != nil {
		returnFailure(w, req,
			fmt.Errorf("transaction parse failed"+err.Error()), 400)
	}

	// 验证
	valid, err := VerifyTransaction(tx)
	if err != nil {
		returnFailure(w, req, err, http.StatusInternalServerError)
		return
	}
	if !valid {
		returnFailure(w, req,
			fmt.Errorf("verification failed"+err.Error()), http.StatusUnauthorized)
		return
	}

	// 处理
	err = serverlib.InitializeNewSenderPKTransaction(tx)
	if err != nil {
		returnFailure(w, req, err, http.StatusBadRequest)
		return
	}

	// 重加密
	swk, err := db.GetSwitchingKeyUserIDInOut(Database, tx.Sender, tx.Receipt)
	if err != nil {
		returnFailure(w, req, err, http.StatusInternalServerError)
		return
	}

	serverlib.KeySwitchSenderToReceipt(tx, swk)

	// 更新余额
	senderBalance, err := db.GetUserBalance(Database, tx.Sender)
	if err != nil {
		returnFailure(w, req, err, 500)
		return
	}
	receiptBalance, err := db.GetUserBalance(Database, tx.Receipt)
	if err != nil {
		returnFailure(w, req, err, 500)
	}
	senderUpdated, receiptUpdated, err := serverlib.GetUpdatedBalance(tx, senderBalance, receiptBalance)

	if err != nil {
		returnFailure(w, req, err, 500)
	}

	err = db.UpdateBalance(Database, tx.Sender, senderUpdated)
	if err != nil {
		returnFailure(w, req, err, 500)
	}
	err = db.UpdateBalance(Database, tx.Receipt, receiptUpdated)
	if err != nil {
		returnFailure(w, req, err, 500)
	}

	serverlib.FinishTransaction(tx)
	if err = db.WriteTransaction(Database, tx); err != nil {
		returnFailure(w, req, err, http.StatusInternalServerError)
		return
	}

	// 处理返回信息
	respData := make(map[string]interface{})
	respData["status"] = "OK"
	respData["transaction"] = tx.CopyToJSONStruct()

	respJSON, err := json.Marshal(respData)
	if err != nil {
		returnFailure(w, req, err, http.StatusInternalServerError)
		return
	}

	w.WriteHeader(200)
	w.Write(respJSON)
	InfoLogger.Print("Proceeded /transaction/create/bySenderPK request")

	// 更新

}

// Handle /transaction/create/byReceiptPK request
func HandlerTransactionCreateByReceiptPK(w http.ResponseWriter, req *http.Request) {
	var err error
	txj := new(transaction.TransactionJSON)

	// 解码
	if err = json.NewDecoder(req.Body).Decode(txj); err != nil {
		returnFailure(w, req, err, http.StatusBadRequest)
		return
	}
	tx, err := txj.CopyToStruct()
	if err != nil {
		returnFailure(w, req,
			fmt.Errorf("transaction parse failed"+err.Error()), 400)
	}

	// 处理交易信息
	// 验证
	valid, err := VerifyTransaction(tx)
	if err != nil {
		returnFailure(w, req, err, http.StatusInternalServerError)
		return
	}
	if !valid {
		returnFailure(w, req,
			fmt.Errorf("verification failed"+err.Error()), http.StatusUnauthorized)
	}

	serverlib.InitializeNewReceiptPKTransaction(tx)

	// 重加密
	swk, err := db.GetSwitchingKeyUserIDInOut(Database, tx.Receipt, tx.Sender)
	if err != nil {
		returnFailure(w, req, err, http.StatusInternalServerError)
	}

	err = serverlib.KeySwitchReceiptToSender(tx, swk)
	if err != nil {
		returnFailure(w, req,
			fmt.Errorf("re-encryption failed: "+err.Error()), 500)
	}

	// 写入数据库
	if err = db.WriteTransaction(Database, tx); err != nil {
		returnFailure(w, req, err, http.StatusInternalServerError)
	}

	// 处理返回信息
	respData := make(map[string]interface{})
	respData["status"] = "OK"
	respData["transaction"] = *tx

	respJSON, err := json.Marshal(respData)
	if err != nil {
		returnFailure(w, req, err, http.StatusInternalServerError)
		return
	}

	w.WriteHeader(200)
	w.Write(respJSON)
}

// Handle /transaction/confirm request
// 这个方法只预期两个输入，及uuid和签名
func HandlerTransactionConfirm(w http.ResponseWriter, req *http.Request) {
	var err error

	jsonData := make(map[string]interface{})
	err = json.NewDecoder(req.Body).Decode(&jsonData)
	if err != nil {
		returnFailure(w, req, err, 400)
		return
	}

	txUUID, err := uuid.Parse(jsonData["uuid"].(string))
	if err != nil {
		returnFailure(w, req,
			fmt.Errorf("uuid parse failed: "+err.Error()), 400)
	}

	// 获取已有的交易信息
	tx, err := db.GetTransaction(Database, txUUID)
	if err != nil {
		returnFailure(w, req,
			fmt.Errorf("get transaction failed: "+err.Error()), 500)
	}

	// 验证交易
	sig := []byte(jsonData["sigCtSender"].(string))
	tx.SigCTSender = sig
	tx.CTSenderSignedBy = tx.Receipt

	valid, err := verifyTransactionConfirmingStage(tx)
	if err != nil {
		returnFailure(w, req, err, http.StatusInternalServerError)
		return
	}
	if !valid {
		returnFailure(w, req,
			fmt.Errorf("verification failed"+err.Error()), http.StatusUnauthorized)
	}

	// 更新交易信息
	err = serverlib.FinishTransaction(tx)
	if err != nil {
		returnFailure(w, req, err, http.StatusInternalServerError)
	}

	// 更新余额
	senderBalance, err := db.GetUserBalance(Database, tx.Sender)
	if err != nil {
		returnFailure(w, req, err, 500)
		return
	}
	receiptBalance, err := db.GetUserBalance(Database, tx.Receipt)
	if err != nil {
		returnFailure(w, req, err, 500)
	}
	senderUpdated, receiptUpdated, err := serverlib.GetUpdatedBalance(tx, senderBalance, receiptBalance)
	if err != nil {
		returnFailure(w, req, err, 500)
	}

	err = db.UpdateBalance(Database, tx.Sender, senderUpdated)
	if err != nil {
		returnFailure(w, req, err, 500)
	}
	err = db.UpdateBalance(Database, tx.Receipt, receiptUpdated)
	if err != nil {
		returnFailure(w, req, err, 500)
	}

	// 写入交易
	if err = db.WriteTransaction(Database, tx); err != nil {
		returnFailure(w, req, err, http.StatusInternalServerError)
	}

	// 处理返回信息
	respData := make(map[string]interface{})
	respData["status"] = "OK"
	respData["transaction"] = tx.CopyToJSONStruct()

	respJSON, err := json.Marshal(respData)
	if err != nil {
		returnFailure(w, req, err, http.StatusInternalServerError)
		return
	}

	w.WriteHeader(200)
	w.Write(respJSON)
}

// Handle /transaction/reject request
func HandlerTransactionReject(w http.ResponseWriter, req *http.Request) {
	jsonData := make(map[string]interface{})
	json.NewDecoder(req.Body).Decode(&jsonData)

	todo(w, req)
}

// Handle /transaction/get
func HandlerTransactionGet(w http.ResponseWriter, req *http.Request) {
	jsonData := make(map[string]interface{})
	json.NewDecoder(req.Body).Decode(&jsonData)

	txUUID, err := uuid.Parse(jsonData["uuid"].(string))
	if err != nil {
		returnFailure(w, req,
			fmt.Errorf("uuid parse failed: "+err.Error()), 400)
	}

	tx, err := db.GetTransaction(Database, txUUID)
	if err != nil {
		returnFailure(w, req,
			fmt.Errorf("get transaction failed: "+err.Error()), 500)
	}

	respData := make(map[string]interface{})
	respData["status"] = "OK"
	respData["transaction"] = *tx

	respJSON, err := json.Marshal(respData)
	if err != nil {
		returnFailure(w, req, err, http.StatusInternalServerError)
		return
	}

	w.WriteHeader(200)
	w.Write(respJSON)
}

// --- 注册部分 ---

// Handle /register/swk
func HandlerRegisterSwk(w http.ResponseWriter, req *http.Request) {
	InfoLogger.Print("Received new /register/swk")
	var err error

	request := new(restfulpayload.RegisterSwkReq)
	err = json.NewDecoder(req.Body).Decode(request)
	if err != nil {
		returnFailure(w, req, err, 400)
		return
	}

	id := uuid.New()

	ckksSwkBytes, err := base64.RawStdEncoding.DecodeString(request.Swk)
	if err != nil {
		returnFailure(w, req,
			fmt.Errorf("ckks swk parse failed"+err.Error()), 400)
		return
	}
	ckksSwk := new(rlwe.SwitchingKey)
	err = ckksSwk.UnmarshalBinary(ckksSwkBytes)
	if err != nil {
		returnFailure(w, req,
			fmt.Errorf("ckks swk parse failed"+err.Error()), 400)
		return
	}
	DebugLogger.Print("Got swk, size = " + fmt.Sprint(ckksSwk.MarshalBinarySize()))

	err = db.PutSwitchingKeyColumnByUserInUserOut(Database, id,
		request.UserIn, request.UserOut, ckksSwk)
	if err != nil {
		returnFailure(w, req, err, http.StatusInternalServerError)
		return
	}

	respData := make(map[string]interface{})
	respData["status"] = "OK"

	respJSON, err := json.Marshal(respData)
	if err != nil {
		returnFailure(w, req, err, http.StatusInternalServerError)
		return
	}

	w.WriteHeader(200)
	w.Write(respJSON)
	InfoLogger.Print("Processed new /register/swk")

}

// Handle /register/User
func HandlerRegisterUser(w http.ResponseWriter, req *http.Request) {
	InfoLogger.Print("Received new /register/user")
	var err error

	request := new(restfulpayload.UserRegisterReq)
	err = json.NewDecoder(req.Body).Decode(request)
	if err != nil {
		returnFailure(w, req, err, 400)
		return
	}

	userName := request.Name
	userUUID := request.UUID

	// Parse CKKS and ECDSA Public Key
	ckksPubkeyBytes, err := base64.RawStdEncoding.DecodeString(request.CKKS_pubkey)
	if err != nil {
		returnFailure(w, req, err, 400)
		return
	}
	if len(ckksPubkeyBytes) == 0 {
		returnFailure(w, req,
			fmt.Errorf("ckks pubkey parse failed"), 400)
		return
	}
	ckksPubkey := rlwe.NewPublicKey(GetCKKSParams().Parameters)
	if err = ckksPubkey.UnmarshalBinary(ckksPubkeyBytes); err != nil {
		returnFailure(w, req,
			fmt.Errorf("ckks pubkey parse failed: "+err.Error()), 400)
		return
	}

	ecdsaPubkeyBytes, err := base64.RawStdEncoding.DecodeString(request.ECDSA_pubkey)
	if err != nil {
		returnFailure(w, req, err, 400)
		return
	}
	if len(ecdsaPubkeyBytes) == 0 {
		returnFailure(w, req,
			fmt.Errorf("ecdsa pubkey parse failed: "+err.Error()), 400)
		return
	}
	var ecdsaPubkey *ecdsa.PublicKey
	if ecdsaPubkeyAny, err := x509.ParsePKIXPublicKey(ecdsaPubkeyBytes); err != nil {
		returnFailure(w, req,
			fmt.Errorf("ecdsa pubkey parse failed: "+err.Error()), 400)
		return
	} else {
		ecdsaPubkey = ecdsaPubkeyAny.(*ecdsa.PublicKey)
	}

	// 写入数据库
	// Fixme: 默认余额允许非0
	usr := users.NewUserWithUserName(userName)
	usr.UserIdentifier = userUUID
	usr.UserCKKSKeyChain = append(usr.UserCKKSKeyChain, key.CKKSKeyChain{
		Identifier:     uuid.New(),
		CKKSPublicKey:  ckksPubkey,
		CKKSPrivateKey: nil,
	})
	usr.UserECDSAKeyChain = append(usr.UserECDSAKeyChain, key.ECDSAKeyChain{
		Identifier:      uuid.New(),
		ECDSAPublicKey:  ecdsaPubkey,
		ECDSAPrivateKey: nil,
	})
	params := GetCKKSParams()
	balance := ckks.NewEncryptor(params, ckksPubkey).EncryptNew(
		ckks.NewEncoder(params).EncodeNew(
			[]float64{0}, params.MaxLevel(), params.DefaultScale(), params.MaxLogSlots(),
		),
	)
	err = db.PutUserColumn(Database, usr, balance)
	if err != nil {
		returnFailure(w, req, err, http.StatusInternalServerError)
		return
	}
	err = db.PutCKKSPublicKeyColumn(
		Database, usr.UserCKKSKeyChain[0].Identifier,
		usr.UserIdentifier, ckksPubkey,
	)
	if err != nil {
		returnFailure(w, req, err, http.StatusInternalServerError)
		return
	}
	err = db.PutECDSAPublicKeyColumn(
		Database, usr.UserECDSAKeyChain[0].Identifier,
		usr.UserIdentifier, ecdsaPubkey,
	)
	if err != nil {
		returnFailure(w, req, err, http.StatusInternalServerError)
		return
	}

	respData := make(map[string]interface{})
	respData["status"] = "OK"

	respJSON, err := json.Marshal(respData)
	if err != nil {
		returnFailure(w, req, err, http.StatusInternalServerError)
		return
	}

	w.WriteHeader(200)
	w.Write(respJSON)
	InfoLogger.Print("Processed new /register/user, uuid = " + userUUID.String())
}

func HandlerUserGetBalance(w http.ResponseWriter, req *http.Request) {
	InfoLogger.Print("Received new /user/getBalance request")
	var err error

	// 复用注册时使用的结构体
	request := new(restfulpayload.UserRegisterReq)
	err = json.NewDecoder(req.Body).Decode(request)
	if err != nil {
		returnFailure(w, req, err, 400)
		return
	}

	userUUID := request.UUID

	// 从数据库中读取
	balance, err := db.GetUserBalance(Database, userUUID)
	if err != nil {
		returnFailure(w, req, err, http.StatusInternalServerError)
		return
	}
	balanceBytes, err := balance.MarshalBinary()
	if err != nil {
		returnFailure(w, req, err, http.StatusInternalServerError)
		return
	}

	balanceString := base64.StdEncoding.EncodeToString(balanceBytes)

	respData := make(map[string]interface{})
	respData["status"] = "OK"
	respData["balance"] = balanceString

	respJSON, err := json.Marshal(respData)
	if err != nil {
		returnFailure(w, req, err, http.StatusInternalServerError)
		return
	}

	w.WriteHeader(200)
	w.Write(respJSON)
	InfoLogger.Print("Processed new /user/getBalance, uuid = " + userUUID.String())
}
