package main

import (
	"fmt"
	"time"

	"github.com/CamberLoid/Chimata/internal/db"
	"github.com/CamberLoid/Chimata/internal/serverlib"
	"github.com/CamberLoid/Chimata/internal/transaction"
)

// VerifyTransaction 验证交易的以下性质：
// - 是否是伪造的？
// - 金额是否足额？
// - 可能的话，验证是否是重复交易
// 需要去数据库搜索用户对应公钥
func VerifyTransaction(tx *transaction.Transaction) (res bool, err error) {
	// 验证足额
	res, err = verifyIfValid(tx)
	if !res || err != nil {
		return false, err
	}

	// 验证签名
	// 逻辑：
	// - 若转出密文由转出者自己签名，则这是一个转出交易
	//   此时接收密文不需要（或者由CA进行）签名
	//   服务端可以直接记账
	// - 若接收密文是由转出者签名：
	//   - 若
	switch {
	case tx.CTSenderSignedBy == tx.Sender:
		res, err = verifyTransactionSenderPK(tx)
	case tx.CTReceiptSignedBy == tx.Sender && len(tx.SigCTSender) == 0:
		res, err = verifyTransactionReceiptPK(tx)
	case len(tx.SigCTReceipt) != 0 && len(tx.SigCTSender) != 0:
		res, err = verifyTransactionConfirmingStage(tx)
	default:
		return false, fmt.Errorf("verification failed: signature, unknown reason")
	}
	if !res || err != nil {
		return res, err
	}

	// 验证是否重复
	// 该部分跳过

	return true, nil
}

// 验证
func verifyTransactionConfirmingStage(tx *transaction.Transaction) (res bool, err error) {
	DebugLogger.Print("Going in verifyTransactionConfirmingStage")
	SignerUUID := tx.CTSenderSignedBy

	// 获取公钥
	_start := time.Now()
	pubkey, err := db.GetECDSAKeyByUserUUID(Database, SignerUUID)
	if err != nil {
		return false, err
	} else {
		DurationDatabaseOpr += time.Since(_start)
	}

	// 验证签名
	res, err = serverlib.ValidateSignatureForAcceptCipherText(tx.CTSender, tx.SigCTSender, pubkey.ECDSAPublicKey)
	if err != nil {
		return false, err
	}
	if !res {
		return false, fmt.Errorf("signature verify failed")
	}

	return true, nil
}

func verifyTransactionSenderPK(tx *transaction.Transaction) (res bool, err error) {
	DebugLogger.Print("Going in verifyTransactionSenderPK")
	SignerUUID := tx.CTSenderSignedBy

	_start := time.Now()
	pubkey, err := db.GetECDSAKeyByUserUUID(Database, SignerUUID)
	if err != nil {
		return false, err
	} else {
		DurationDatabaseOpr += time.Since(_start)
	}

	res, err = serverlib.ValidateSignatureForCipherText(tx.CTSender, tx.SigCTSender, pubkey.ECDSAPublicKey)

	if err != nil {
		return false, err
	}
	if !res {
		return false, fmt.Errorf("signature verify failed")
	}

	return true, nil
}

func verifyTransactionReceiptPK(tx *transaction.Transaction) (res bool, err error) {
	DebugLogger.Print("Going in verifyTransactionReceiptPK")
	SignerUUID := tx.CTReceiptSignedBy

	_start := time.Now()
	pubkey, err := db.GetECDSAKeyByUserUUID(Database, SignerUUID)
	if err != nil {
		return false, fmt.Errorf("internal database error: %v", err)
	} else {
		DurationDatabaseOpr += time.Since(_start)
	}

	res, err = serverlib.ValidateSignatureForCipherText(tx.CTReceipt, tx.SigCTReceipt, pubkey.ECDSAPublicKey)

	if err != nil {
		return false, fmt.Errorf("internal verify error: %v", err)
	}
	if !res {
		return false, fmt.Errorf("signature verify failed")
	}

	return true, nil
}

// 验证是否足额
// 涉及到与 CA 的交互，暂时忽略
func verifyIfValid(tx *transaction.Transaction) (res bool, err error) {
	// 还没写！
	ErrorLogger.Println("CA not implemented yet")
	return true, nil
}
