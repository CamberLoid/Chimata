// 包 db 包含共用的sql操作方法
package db

import (
	_ "github.com/mattn/go-sqlite3"
)

// --- 数据库具体操作 ---
// --- 初始化：建表 ---

// table Transactions
func CreateTransactionTable() string {
	return `
        CREATE TABLE IF NOT EXISTS Transactions (
            uuid TEXT PRIMARY KEY NOT NULL,
            confirming_phase TEXT,
            sender TEXT,
            receipt TEXT,
            ct_sender BLOB,
            ct_receipt BLOB,
            sig_ct_sender BLOB,
            ct_sender_signed_by BLOB,
            sig_ct_receipt BLOB,
            ct_receipt_signed_by BLOB,
            timestamp INTEGER,
            is_valid INTEGER,
			FOREIGN KEY(sender) REFERENCES Users(uuid)
			FOREIGN KEY(receipt) REFERENCES Users(uuid)
        );
    `
}

// table Users:
// uuid TEXT PRIMARY KEY,
// userName TEXT
// balance BLOB <- []byte 被 rlwe.CipherText.Marshall编码
// primary{ECDSA, CKKS}Key <- uuid, TEXT
func CreateUserTable() string {
	return `
		CREATE TABLE IF NOT EXISTS Users (
			uuid TEXT PRIMARY KEY,
			userName TEXT,
			balance BLOB,
			primaryCKKSKeyID TEXT,
			primaryECDSAKeyID TEXT
		);
	`
}

// table SwitchingKey
// uuid TEXT PRIMARY KEY
// userIn TEXT, as FOREIGN KEY Users(uuid)
// userOut TEXT, as FOREIGN KEY to Users(uuid)
// pkIn, pkOut BLOB, as FOREIGN KEY to CKKSKeyChains(uuid)
// SwitchingKey BLOB
func CreateSwitchingKeyTable() string {
	return `
		CREATE TABLE IF NOT EXISTS SwitchingKeys(
			uuid TEXT PRIMARY KEY,
			userIn TEXT,
			userOut TEXT,
			pkIn TEXT,
			pkOut TEXT,
			SwitchingKey BLOB NOT NULL,
			FOREIGN KEY (userIn) REFERENCES Users(uuid),
			FOREIGN KEY (userOut) REFERENCES Users(uuid),
			FOREIGN KEY (pkIn) REFERENCES CKKSKeyChains(uuid),
			FOREIGN KEY (pkOut) REFERENCES CKKSKeyChains(uuid)
		);
	`
}

// table CKKSKeyChains
// uuid TEXT 作为主键
// user TEXT 作为指向 Users(uuid) 的外键, cannot be null
// publicKey blob, cannot be null
// evaluationKey blob, which may be null
// isMain integer, which would be boolean in golang, and for each user they can only have one column tagged isMain = true

// CreateCKKSKeyTable 新的 CKKS 公钥表
func CreateCKKSKeyTable() string {
	return `
		CREATE TABLE IF NOT EXISTS CKKSKeyChains (
			uuid TEXT PRIMARY KEY,
			user TEXT NOT NULL REFERENCES Users(uuid),
			publicKey BLOB NOT NULL,
			evaluationKey BLOB,
			privateKey BLOB
		);
	`
}

// table ECDSAKeyChains
// uuid TEXT
// user TEXT as FOREIGN KEY
// publicKey BLOB

// createECDSAKeyChainsTable 创建新的ECDSA公钥表
func CreateECDSAKeyTable() string {
	return `
		CREATE TABLE IF NOT EXISTS ECDSAKeyChains (
			uuid TEXT PRIMARY KEY,
			user TEXT NOT NULL REFERENCES Users(uuid),
			publicKey BLOB NOT NULL,
			privateKey BLOB
		);
	`
}
