package clientlib

import (
	"database/sql"
	"errors"
	"fmt"

	"github.com/CamberLoid/Chimata/internal/db"
	"github.com/CamberLoid/Chimata/internal/transaction"
	"github.com/google/uuid"
	_ "github.com/mattn/go-sqlite3"
	"github.com/tuneinsight/lattigo/v4/rlwe"
)

type Client struct {
	Database *sql.DB
	MainUser User
}

func NewClient(dbPath string, mainUser User) (c *Client, err error) {
	db, err := sql.Open("sqlite3", dbPath)
	if err != nil {
		return nil, err
	}
	return &Client{db, mainUser}, err
}

// 转账任务
func (c Client) TransferViaUser(u *User, amount float64, method string) (err error) {
	switch method {
	case "sender", "Sender":
		return c.transferViaUserViaSenderPK(u, amount)
	case "receipt", "Receipt":
		return c.transferViaUserViaReceiptPK(u, amount)
	}

	return nil
}

func (c Client) transferViaUserViaSenderPK(r *User, amount float64) (err error) {
	tx, err := c.MainUser.TransferBySenderPK(r, amount)
	if err != nil {
		return err
	}
	ntx, err := c.MainUser.CreateTransferJob(tx)
	if err != nil {
		return err
	}
	err = db.WriteTransaction(c.Database, ntx)
	return
}

func (c Client) transferViaUserViaReceiptPK(r *User, amount float64) (err error) {
	tx, err := c.MainUser.TransferByReceiptPK(r, amount)
	if err != nil {
		return err
	}
	ntx, err := c.MainUser.CreateTransferJob(tx)
	if err != nil {
		return err
	}
	err = db.WriteTransaction(c.Database, ntx)
	return
}

func (c Client) ConfirmTransaction(t *transaction.Transaction) (err error) {
	_, err = c.MainUser.AcceptTransactionByTransaction(t)
	if err != nil {
		return
	}
	err = c.MainUser.CreateConfirmTransactionTask(t)
	return
}

func (c Client) GetTransactionAmount(t interface{}) (amount float64, err error) {
	switch v := t.(type) {
	case uuid.UUID:
		tx, err := GetTransactionFromServer(t.(uuid.UUID))
		if err != nil {
			return 0, err
		}
		return c.getTransactionAmount(tx)
	case *transaction.Transaction:
		return c.getTransactionAmount(t.(*transaction.Transaction))
	default:
		return 0, fmt.Errorf("unknown type %T", v)
	}
}

func (c Client) getTransactionAmount(t *transaction.Transaction) (amount float64, err error) {
	id := c.MainUser.UserIdentifier
	var ct *rlwe.Ciphertext
	if t.Sender == id {
		ct, err = t.GetSenderCT()
		if err != nil {
			return 0, err
		}
		return c.MainUser.DecryptAmountFromCT(ct)
	} else if t.Receipt == id {
		ct, err = t.GetReceiptCT()
		if err != nil {
			return 0, err
		}
		return c.MainUser.DecryptAmountFromCT(ct)
	} else {
		return 0, errors.New("not user's ciphertext!")
	}
}
