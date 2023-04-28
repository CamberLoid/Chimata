package db

import (
	"crypto/ecdsa"
	"crypto/x509"
	"database/sql"
	"encoding/json"
	"fmt"

	"github.com/CamberLoid/Chimata/internal/key"
	"github.com/CamberLoid/Chimata/internal/transaction"
	"github.com/CamberLoid/Chimata/internal/users"
	"github.com/google/uuid"
	_ "github.com/mattn/go-sqlite3"
	"github.com/pkg/errors"
	"github.com/tuneinsight/lattigo/v4/ckks"
	"github.com/tuneinsight/lattigo/v4/rlwe"
)

func GetTransaction(db *sql.DB, txUUID uuid.UUID) (tx *transaction.Transaction, err error) {
	stmt, err := db.Prepare(`
	SELECT confirmingPhase, uuid, sender, receipt,
		ctSender, ctReceipt, sigCtSender, ctSenderSignedBy,
		sigCTReceipt, ctReceiptSignedBy, timeStamp, isValid
	FROM Transactions
	WHERE uuid = ?
`)
	if err != nil {
		return nil, errors.Wrap(err, "prepare statement")
	}
	defer stmt.Close()

	// 执行查询
	row := stmt.QueryRow(txUUID.String())

	// 将查询结果映射到结构体
	var txJSON string
	tx = &transaction.Transaction{}
	err = row.Scan(
		&tx.ConfirmingPhase,
		&tx.UUID,
		&tx.Sender,
		&tx.Receipt,
		&tx.CTSender,
		&tx.CTReceipt,
		&tx.SigCTSender,
		&tx.CTSenderSignedBy,
		&tx.SigCTReceipt,
		&tx.CTReceiptSignedBy,
		&tx.TimeStamp,
		&tx.IsValid,
	)
	if err != nil {
		return nil, errors.Wrap(err, "scan row")
	}

	// 反序列化 JSON 字符串到 tx 对象
	err = json.Unmarshal([]byte(txJSON), tx)
	if err != nil {
		return nil, errors.Wrap(err, "unmarshal json")
	}

	return tx, nil
}

// 查询用户余额
func GetUserBalance(db *sql.DB, UserUUID uuid.UUID) (balance *rlwe.Ciphertext, err error) {
	row, err := db.Query(`
		SELECT balance
		FROM Users
		WHERE uuid = ?;
		`, UserUUID,
	)
	if err != nil {
		return nil, err
	}
	defer row.Close()

	params, _ := ckks.NewParametersFromLiteral(ckks.PN12QP109)
	balance = rlwe.NewCiphertext(
		params.Parameters, 1, params.MaxLevel(),
	)
	var balanceBytes []byte

	if row.Scan(&balanceBytes) != nil {
		return nil, fmt.Errorf("failed to scan balance bytes: %v", err)
	}

	err = balance.UnmarshalBinary(balanceBytes)

	return
}

func GetECDSAKeyByUserUUID(db *sql.DB, UserUUID uuid.UUID) (keyChain *key.ECDSAKeyChain, err error) {
	keyChain = new(key.ECDSAKeyChain)
	row, err := db.Query(`
		SELECT uuid, publicKey, privateKey
		FROM ECDSAPublicKeys
		WHERE user = ?;
		`, UserUUID,
	)
	if err != nil {
		return nil, err
	}
	defer row.Close()

	var pubkeyBytes, privateKeyBytes []byte
	var identifier uuid.UUID

	if row.Scan(&identifier, &pubkeyBytes, &privateKeyBytes) != nil {
		return nil, fmt.Errorf("failed to scan ECDSA key bytes: %v", err)
	}

	keyChain.Identifier = identifier

	// 处理公钥
	_pubkey, err := x509.ParsePKIXPublicKey(pubkeyBytes)
	if err != nil {
		return nil, err
	}
	switch v := _pubkey.(type) {
	case *ecdsa.PublicKey:
		keyChain.ECDSAPublicKey = _pubkey.(*ecdsa.PublicKey)
	default:
		return nil, fmt.Errorf("not a ecdsa public key, got %v", v)
	}

	// 处理可能的私钥
	if len(privateKeyBytes) != 0 {
		_privkey, err := x509.ParseECPrivateKey(privateKeyBytes)
		if err == nil {
			keyChain.ECDSAPrivateKey = _privkey
		}
		return keyChain, nil
	} else {
		return
	}
}

func GetCKKSKeyByUserUUID(db *sql.DB, UserUUID uuid.UUID) (keyChain *key.CKKSKeyChain, err error) {
	// 初始化
	keyChain = new(key.CKKSKeyChain)
	params, _ := ckks.NewParametersFromLiteral(ckks.PN12QP109)
	privkey := rlwe.NewSecretKey(params.Parameters)
	var pubkeyBytes, privateKeyBytes []byte
	var id []byte

	// 查询
	row, err := db.Query(`
		SELECT uuid, publicKey, privateKey
		FROM CKKSPublicKeys
		WHERE user = ?;
		`, UserUUID,
	)
	if err != nil {
		return nil, err
	}
	defer row.Close()

	if row.Scan(&id, &pubkeyBytes, &privateKeyBytes) != nil {
		return nil, fmt.Errorf("failed to scan CKKS public key bytes: %v", err)
	}
	keyChain.Identifier = uuid.MustParse(string(id))

	if err = keyChain.CKKSPublicKey.UnmarshalBinary(pubkeyBytes); err != nil {
		return nil, err
	}

	if len(privateKeyBytes) != 0 {
		err = privkey.UnmarshalBinary(privateKeyBytes)
		if err == nil {
			keyChain.CKKSPrivateKey = privkey
		} else {
			return keyChain, err
		}
	}
	return keyChain, nil
}

func GetSwitchingKeyPKInPKOut(db *sql.DB, pkIDIn, pkIDOut uuid.UUID) (swk *rlwe.SwitchingKey, err error) {
	params, _ := ckks.NewParametersFromLiteral(ckks.PN12QP109)
	swk = rlwe.NewSwitchingKey(params.Parameters, params.RingQ().NewPoly().Level(), params.RingP().NewPoly().Level())

	row, err := db.Query(`
		SELECT switchingKey FROM SwitchingKeys
		WHERE pkIDIn = ? AND pkIDOut = ?;
	`, pkIDIn, pkIDOut)

	if err != nil {
		return nil, err
	}
	defer row.Close()

	var swkByte []byte
	if row.Scan(&swkByte) != nil {
		return nil, fmt.Errorf("failed to scan switching key: %v", err)
	}
	err = swk.UnmarshalBinary(swkByte)

	return
}

func GetSwitchingKeyUserIDInOut(db *sql.DB, UserIDIn, UserIDOut uuid.UUID) (swk *rlwe.SwitchingKey, err error) {
	params, _ := ckks.NewParametersFromLiteral(ckks.PN12QP109)
	swk = rlwe.NewSwitchingKey(params.Parameters, params.RingQ().NewPoly().Level(), params.RingP().NewPoly().Level())

	row, err := db.Query(`
		SELECT switchingKey FROM SwitchingKeys
		WHERE pkIDIn = ? AND pkIDOut = ?;
	`, UserIDIn, UserIDOut)

	if err != nil {
		return nil, err
	}
	defer row.Close()

	var swkByte []byte
	if row.Scan(&swkByte) != nil {
		return nil, fmt.Errorf("failed to scan switching key: %v", err)
	}
	err = swk.UnmarshalBinary(swkByte)

	return
}

func GetUser(db *sql.DB, UserUUID uuid.UUID) (user *users.User, err error) {
	var (
		ckksKeychain  *key.CKKSKeyChain
		ecdsaKeychain *key.ECDSAKeyChain
		id            string
	)
	user = new(users.User)

	row, err := db.Query(`
		SELECT uuid, userName
		FROM Users
		WHERE uuid = ?;
		`, UserUUID,
	)
	if err != nil {
		return nil, err
	}
	defer row.Close()

	if row.Scan(&id, &user.UserName) != nil {
		return nil, fmt.Errorf("failed to scan user: %v", err)
	}
	user.UserIdentifier = uuid.MustParse(id)

	ckksKeychain, err = GetCKKSKeyByUserUUID(db, user.UserIdentifier)
	if err != nil && ckksKeychain == nil {
		return nil, err
	}

	ecdsaKeychain, err = GetECDSAKeyByUserUUID(db, user.UserIdentifier)
	if err != nil && ecdsaKeychain == nil {
		return nil, err
	}

	user.UserCKKSKeyChain = append(user.UserCKKSKeyChain, *ckksKeychain)
	user.UserECDSAKeyChain = append(user.UserECDSAKeyChain, *ecdsaKeychain)

	return user, nil
}

// --- 写入部分 ---

// TODO: 检查是否uuid重复
// 但uuid为服务端生成且概率很低()，不考虑了
// ref: https://scaleyourapp.com/uuid-guid-oversimplified-are-they-really-unique/
// note: https://stackoverflow.com/questions/37145935/checking-if-a-value-exists-in-sqlite-db-with-go

// WriteTransaction 将交易写入/更新至数据库
func WriteTransaction(db *sql.DB, tx *transaction.Transaction) (err error) {
	stmt, err := db.Prepare(`
		INSERT INTO Transactions (
			ConfirmingPhase, UUID, Sender, Receipt, CTSender, CTReceipt,
			SigCTSender, CTSenderSignedBy, SigCTReceipt, CTReceiptSignedBy,
			TimeStamp, IsValid
		)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT (uuid) DO UPDATE
        SET
            sender = excluded.sender,
            receipt = excluded.receipt,
            ct_sender = excluded.ct_sender,
            ct_receipt = excluded.ct_receipt,
            sig_ct_sender = excluded.sig_ct_sender,
            ct_sender_signed_by = excluded.ct_sender_signed_by,
            sig_ct_receipt = excluded.sig_ct_receipt,
            ct_receipt_signed_by = excluded.ct_receipt_signed_by,
            timestamp = excluded.timestamp,
            is_valid = excluded.is_valid,
            confirming_phase = excluded.confirming_phase
	`)
	if err != nil {
		return err
	}
	defer stmt.Close()

	// 将结构体字段映射到 SQL 参数上
	_, err = stmt.Exec(
		tx.ConfirmingPhase, tx.UUID.String(), tx.Sender.String(), tx.Receipt.String(),
		tx.CTSender, tx.CTReceipt, tx.SigCTSender, tx.CTSenderSignedBy.String(),
		tx.SigCTReceipt, tx.CTReceiptSignedBy.String(), tx.TimeStamp, tx.IsValid,
	)
	if err != nil {
		return err
	}
	return
}

// UpdateBalance 更新数据库中用户余额
func UpdateBalance(db *sql.DB, userUUID uuid.UUID, balance *rlwe.Ciphertext) (err error) {
	balanceByte, err := balance.MarshalBinary()
	if err != nil {
		return err
	}

	stmt, err := db.Prepare(`
		UPDATE Balances SET balance = ? WHERE user_uuid = ?
	`)
	if err != nil {
		return err
	}
	defer stmt.Close()

	_, err = stmt.Exec(balanceByte, userUUID.String())
	if err != nil {
		return err
	}

	return nil
}

// 添加新的用户
func PutUserColumn(db *sql.DB, u *users.User, balance *rlwe.Ciphertext) (err error) {
	stmt, err := db.Prepare(`
		INSERT INTO Users 
		(uuid, username, balance)
		VALUES (?, ?, ?)
		ON CONFLICT (uuid) DO UPDATE SET
			username = excluded.username,
			balance = excluded.balance
	`)
	if err != nil {
		return err
	}
	defer stmt.Close()

	_, err = stmt.Exec(u.UserIdentifier, u.UserName, nil)

	if balance != nil {
		return UpdateBalance(db, u.UserIdentifier, balance)
	}

	return
}

// PutCKKSPublicKeyColumn 创建新的CKKS公钥行
func PutCKKSPublicKeyColumn(db *sql.DB, keyID, userID uuid.UUID, pk *rlwe.PublicKey) (err error) {
	pkBytes, err := pk.MarshalBinary()
	if err != nil {
		return err
	}

	stmt, err := db.Prepare(`
		INSERT INTO CKKSPublicKeys
		(uuid, user, publicKey)
		VALUES
		(?,?,?)
	`)
	if err != nil {
		return err
	}
	defer stmt.Close()

	_, err = stmt.Exec(keyID, userID, pkBytes)
	return
}

// PutECDSAPublicKeyColumn 创建新的ECDSA公钥行
func PutECDSAPublicKeyColumn(db *sql.DB, keyID, userID uuid.UUID, pk *ecdsa.PublicKey) (err error) {
	pkBytes, err := x509.MarshalPKIXPublicKey(pk)
	if err != nil {
		return err
	}

	stmt, err := db.Prepare(`
		INSERT INTO ECDSAPublicKeys 
		(uuid, user, publicKey)
		VALUES
		(?, ?, ?)
	`)
	if err != nil {
		return err
	}
	defer stmt.Close()

	_, err = stmt.Exec(keyID, userID, pkBytes)
	return
}

// PutSwitchingKeyColumnByUserInUserOut 创建新的SwitchingKey行
func PutSwitchingKeyColumnByUserInUserOut(db *sql.DB, keyID, userIn, userOut uuid.UUID, swk *rlwe.SwitchingKey) (err error) {
	swkBytes, err := swk.MarshalBinary()
	if err != nil {
		return err
	}

	stmt, err := db.Prepare(`
		INSERT INTO SwitchingKey
		(uuid, userIn, userOut, SwitchingKey)
		VALUES
		(?, ?, ?, ?)
	`)
	if err != nil {
		return err
	}
	defer stmt.Close()

	_, err = stmt.Exec(keyID, userIn, userOut, swkBytes)
	return

}
