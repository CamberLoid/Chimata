package transaction

import (
	"errors"

	"github.com/google/uuid"
	"github.com/tuneinsight/lattigo/v4/ckks"
	"github.com/tuneinsight/lattigo/v4/rlwe"
)

// Transaction 是单笔转账的抽象，
// 一个 Transaction 包含了转账的发起者、接收者、金额、时间戳等信息。具体如下：
// sender, receipt, CT{Sender,Receipt}SignedBy: []byte, UUID
// CTSender,CTReceipt: []byte <- rlwe.CipherText.MarshalBinary()
// sig(略): []byte，签名，只会有三种可能的签名方：CA、发送者和接受者
type Transaction struct {
	// ConfirmingPhase 可能是
	// "unconfirmed", "waiting", "processing",
	// "rejected", "confirmed", "failed"
	ConfirmingPhase   string    `json:"confirmingPhase"`
	UUID              uuid.UUID `json:"uuid"`
	Sender            uuid.UUID `json:"sender"`
	Receipt           uuid.UUID `json:"receipt"`
	CTSender          []byte    `json:"ctSender"`
	CTReceipt         []byte    `json:"ctReceipt"`
	SigCTSender       []byte    `json:"sigCtSender"`
	CTSenderSignedBy  uuid.UUID `json:"ctSenderSignedBy"`
	SigCTReceipt      []byte    `json:"sigCTReceipt"`
	CTReceiptSignedBy uuid.UUID `json:"ctReceiptSignedBy"`
	TimeStamp         int64     `json:"timestamp"` //unix时间戳
	IsValid           bool      `json:"isValid"`
}

func (t Transaction) GetSenderCT() (ct *rlwe.Ciphertext, err error) {
	params, _ := ckks.NewParametersFromLiteral(ckks.PN12QP109)
	ct = ckks.NewCiphertext(
		params, 1, params.MaxLevel(),
	)

	if t.CTSender == nil {
		err = errors.New("no sender ciphertext found")
	} else {
		err = ct.UnmarshalBinary(t.CTSender)
	}

	return
}

func (t Transaction) GetReceiptCT() (ct *rlwe.Ciphertext, err error) {
	params, _ := ckks.NewParametersFromLiteral(ckks.PN12QP109)
	ct = ckks.NewCiphertext(
		params, 1, params.MaxLevel(),
	)

	if t.CTReceipt == nil {
		err = errors.New("no receipt ciphertext found")
	} else {
		err = ct.UnmarshalBinary(t.CTReceipt)
	}

	return
}

// --- 手续费计算，预留 --- //

// CalcFixedFee 计算固定费率的手续费
// ... 返回加了手续费的密文
func CalcFixedFee(ct *rlwe.Ciphertext, rate float64) (fee *rlwe.Ciphertext) {
	params, _ := ckks.NewParametersFromLiteral(ckks.PN12QP109)
	evaluator := ckks.NewEvaluator(params, rlwe.EvaluationKey{})

	fee = evaluator.AddConstNew(ct, rate)

	return
}

// CalcRatedFee 计算按比例计算的手续费
func CalcRatedFee(ct *rlwe.Ciphertext, rate float64) (fee *rlwe.Ciphertext) {
	params, _ := ckks.NewParametersFromLiteral(ckks.PN12QP109)
	evaluator := ckks.NewEvaluator(params, rlwe.EvaluationKey{})

	fee = evaluator.MultByConstNew(ct, rate)

	return
}
