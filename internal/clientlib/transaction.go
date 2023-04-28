// Transaction.go 用于定义转账相关的接口和函数

package clientlib

import (
	"errors"

	"github.com/CamberLoid/Chimata/internal/transaction"
	"github.com/google/uuid"
	"github.com/tuneinsight/lattigo/v4/rlwe"
)

// --- 转账转出部分

// NewOutgoingTransaction 以用户为接收器生成一个新的转账交易
func (u User) NewOutgoingTransaction(receipt *User) (t *transaction.Transaction, err error) {
	t = new(transaction.Transaction)
	t.Sender = u.UserIdentifier
	t.Receipt = receipt.UserIdentifier
	return t, nil
}

// TransferBySenderPK 使用发送方的密钥链对金额进行加密并签名，
// 输出：一个新的 Transaction
func (u User) TransferBySenderPK(receipt *User, amount float64) (t *transaction.Transaction, err error) {
	ct, sig, err := u.makeTransferWithCKKS(u.User.UserCKKSKeyChain[0].CKKSPublicKey, amount)

	t, err = u.NewOutgoingTransaction(receipt)
	t.CTSender, err = ct.MarshalBinary()
	if err != nil {
		return nil, err
	}

	t.SigCTSender = sig
	t.CTSenderSignedBy = u.UserIdentifier

	return
}

// TransferBySenderPK 使用发送方的密钥链对金额进行加密并签名，
// 输入：接收用户，金额明文
// 输出：一个新的Transaction
func (u User) TransferByReceiptPK(receipt *User, amount float64) (t *transaction.Transaction, err error) {
	ct, sig, err := u.makeTransferWithCKKS(receipt.User.UserCKKSKeyChain[0].CKKSPublicKey, amount)

	t, err = u.NewOutgoingTransaction(receipt)

	t.CTReceipt, err = ct.MarshalBinary()
	if err != nil {
		return nil, err
	}

	t.SigCTReceipt = sig
	t.CTReceiptSignedBy = u.UserIdentifier
	t.ConfirmingPhase = "unconfirmed"

	// err = u.CreateTransferJob(t)

	return
}

// 私有方法 makeTransferWithCKKS 将金额 amount 加密，然后签名。
// 输入：目标公钥，金额明文
// 输出：金额密文，签名，错误
func (u User) makeTransferWithCKKS(pk *rlwe.PublicKey, amount float64) (ct *rlwe.Ciphertext, sig []byte, err error) {
	// 将金额转换为 CKKS 密文
	ct = CKKSEncryptAmount(amount, pk)
	sig, err = u.Sign(*ct)

	return
}

// VerifyAmountIsMoreThanBalance 客户端验证余额是否足够
// 输入：金额明文
// 输出：是否足够，错误
func (u User) VerifyAmountIsMoreThanBalance(amount float64) (result bool, err error) {
	balance, err := u.GetBalance()
	return balance > amount, err
}

// --- 接受转账部分 ---
// 在服务端处理接收了转账请求后，如果需要接收方接收转账，需要提前进行重加密
// 即，CTSender 此时被赋值为 KeySwitch(CTReceipt, swk)
// 需要接收方对密文进行签名 "ACCEPT" + CTSender

func (u User) AcceptTransaction(t interface{}) (sig []byte, err error) {
	errText := "unrecognized transaction type, accept Transaction or [16]byte"
	switch t.(type) {
	case *transaction.Transaction, transaction.Transaction:
		err = nil //todo
	case [16]byte, uuid.UUID:
		err = nil //todo
	case []byte:
		if len(t.([]byte)) != 16 {
			err = errors.New(errText)
		}
	default:
		err = errors.New(errText)
		return
	}
	return

}

func (u User) AcceptTransactionByTransaction(t *transaction.Transaction) (sig []byte, err error) {
	// 生成签名
	sig, err = signByte([]byte("ACCEPT"+string(t.CTSender)), u.UserECDSAKeyChain[0].ECDSAPrivateKey)
	if err != nil {
		return nil, err
	}

	t.CTSenderSignedBy = u.UserIdentifier
	t.SigCTSender = sig

	return
}

func (u User) AcceptTransactionByUUID(uuid uuid.UUID) (sig []byte, err error) {
	// todo
	t := new(transaction.Transaction)
	// 向服务端或数据库查询交易

	return u.AcceptTransactionByTransaction(t)
}

func (u User) RejectTransactionByTransaction()
