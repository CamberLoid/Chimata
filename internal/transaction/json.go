package transaction

import (
	"encoding/base64"
	"encoding/json"

	"github.com/google/uuid"
)

// TransactionJSON 结构题和 Transaction 一样，只是为了 json 序列化。
// 不同的是，其将所有的 []byte 类型都变换为了 string 类型。
type TransactionJSON struct {
	// ConfirmingPhase 可能是
	// "unconfirmed", "waiting", "processing",
	// "rejected", "confirmed", "failed"
	ConfirmingPhase   string    `json:"confirmingPhase"`
	UUID              uuid.UUID `json:"uuid"`
	Sender            uuid.UUID `json:"sender"`
	Receipt           uuid.UUID `json:"receipt"`
	CTSender          string    `json:"ctSender"`
	CTReceipt         string    `json:"ctReceipt"`
	SigCTSender       string    `json:"sigCtSender"`
	CTSenderSignedBy  uuid.UUID `json:"ctSenderSignedBy"`
	SigCTReceipt      string    `json:"sigCTReceipt"`
	CTReceiptSignedBy uuid.UUID `json:"ctReceiptSignedBy"`
	TimeStamp         int64     `json:"timestamp"` //unix时间戳
	IsValid           bool      `json:"isValid"`
}

func (t Transaction) CopyToJSONStruct() (res *TransactionJSON) {
	res = new(TransactionJSON)
	// Copy all non-[]byte fields
	res.ConfirmingPhase = t.ConfirmingPhase
	res.UUID = t.UUID
	res.Sender = t.Sender
	res.Receipt = t.Receipt
	res.CTSenderSignedBy = t.CTSenderSignedBy
	res.CTReceiptSignedBy = t.CTReceiptSignedBy
	res.TimeStamp = t.TimeStamp
	res.IsValid = t.IsValid

	// Encode []byte fields to base64
	res.SigCTReceipt = base64.StdEncoding.EncodeToString(t.SigCTReceipt)
	res.SigCTSender = base64.StdEncoding.EncodeToString(t.SigCTSender)
	res.CTReceipt = base64.StdEncoding.EncodeToString(t.CTReceipt)
	res.CTSender = base64.StdEncoding.EncodeToString(t.CTSender)

	return
}

func (tj TransactionJSON) CopyToStruct() (res *Transaction, err error) {
	res = new(Transaction)
	// Copy all non-[]byte fields
	res.ConfirmingPhase = tj.ConfirmingPhase
	res.UUID = tj.UUID
	res.Sender = tj.Sender
	res.Receipt = tj.Receipt
	res.CTSenderSignedBy = tj.CTSenderSignedBy
	res.CTReceiptSignedBy = tj.CTReceiptSignedBy
	res.TimeStamp = tj.TimeStamp
	res.IsValid = tj.IsValid

	// Decode base64 fields to []byte
	res.SigCTReceipt, err = base64.StdEncoding.DecodeString(tj.SigCTReceipt)
	if err != nil {
		return
	}
	res.SigCTSender, err = base64.StdEncoding.DecodeString(tj.SigCTSender)
	if err != nil {
		return
	}
	res.CTReceipt, err = base64.StdEncoding.DecodeString(tj.CTReceipt)
	if err != nil {
		return
	}
	res.CTSender, err = base64.StdEncoding.DecodeString(tj.CTSender)
	if err != nil {
		return
	}

	return
}

func (t Transaction) MarshalToJSON() (res []byte, err error) {
	return json.Marshal(t)
}
