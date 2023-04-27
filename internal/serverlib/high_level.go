package serverlib

import (
	"fmt"

	"github.com/CamberLoid/Chimata/internal/transaction"
	"github.com/google/uuid"
	"github.com/tuneinsight/lattigo/v4/ckks"
	"github.com/tuneinsight/lattigo/v4/rlwe"
)

// --- 高层次进行重加密的函数 ---

func KeySwitchSenderToReceipt(t *transaction.Transaction, swk *rlwe.SwitchingKey) (err error) {
	params, _ := ckks.NewParametersFromLiteral(ckks.PN12QP109)
	ctIn := ckks.NewCiphertext(params, 1, params.MaxLevel())

	err = ctIn.UnmarshalBinary(t.CTSender)
	if err != nil {
		return fmt.Errorf("unmarshal ct failed: " + err.Error())
	}

	ctOut, err := ReEncryptCTWithSwk(ctIn, swk)
	if err != nil {
		return err
	}

	ctOutByte, _ := ctOut.MarshalBinary()
	t.CTReceipt = ctOutByte
	return
}

func KeySwitchReceiptToSender(t *transaction.Transaction, swk *rlwe.SwitchingKey) (err error) {
	params, _ := ckks.NewParametersFromLiteral(ckks.PN12QP109)
	ctIn := ckks.NewCiphertext(params, 1, params.MaxLevel())

	err = ctIn.UnmarshalBinary(t.CTReceipt)
	if err != nil {
		return fmt.Errorf("unmarshal ct failed: " + err.Error())
	}

	ctOut, err := ReEncryptCTWithSwk(ctIn, swk)
	if err != nil {
		return err
	}

	ctOutByte, _ := ctOut.MarshalBinary()
	t.CTSender = ctOutByte
	return
}

// --- CA 交互函数 ---

// RequestSwitchingKey 向 CA 请求重加密密钥
func RequestSwitchingKey(uIn, uOut *uuid.UUID, caUrl string) (swk *rlwe.SwitchingKey, err error) {
	return nil, fmt.Errorf("todo")
}
