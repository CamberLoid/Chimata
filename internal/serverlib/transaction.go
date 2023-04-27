package serverlib

import (
	"fmt"
	"time"

	"github.com/CamberLoid/Chimata/internal/transaction"
	"github.com/google/uuid"
)

// 向交易写入基础数据

func InitializeNewReceiptPKTransaction(t *transaction.Transaction) (err error) {
	t.ConfirmingPhase = "processing"
	if t.CTReceipt == nil {
		return fmt.Errorf("no CTReceipt found in transaction")
	}

	// 分配 uuid
	if _, err = uuid.Parse(string(t.UUID[:])); err != nil {
		err = nil
		t.UUID = uuid.New()
	}

	return
}

func InitializeNewSenderPKTransaction(t *transaction.Transaction) (err error) {
	t.ConfirmingPhase = "processing"
	if t.CTSender == nil {
		return fmt.Errorf("no CTSender found in transaction")
	}

	if _, err = uuid.Parse(string(t.UUID[:])); err != nil {
		err = nil
		t.UUID = uuid.New()
	}

	return
}

// FinishTransaction 将交易标记为已完成
// 该方法应该在交易完成，签名验证后，且更新交易双方账户后使用
func FinishTransaction(t *transaction.Transaction) (err error) {
	t.TimeStamp = time.Now().Unix()
	t.ConfirmingPhase = "confirmed"
	return
}
