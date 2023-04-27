package main

import (
	"database/sql"
	"os"

	database "github.com/CamberLoid/Chimata/internal/db"

	_ "github.com/mattn/go-sqlite3"
)

const (
	DefaultDatabaseDirPath  string = "/.config/Chimata/"
	DefaultDatabaseFileName string = "server.db"
)

var (
	homedir, _                = os.UserHomeDir()
	ConfigDatabasePath string = homedir + DefaultDatabaseDirPath + DefaultDatabaseFileName
)

func InitDatabase() (db *sql.DB, err error) {
	if _, err = os.Stat(ConfigDatabasePath); os.IsNotExist(err) {
		if ConfigDatabasePath == homedir+DefaultDatabaseDirPath+DefaultDatabaseFileName {
			// 创建这么一个文件夹
			err = os.MkdirAll(homedir+DefaultDatabaseDirPath, 0700)
			if err != nil {
				return nil, err
			}
		} else {
			return nil, err
		}

	}

	return initDatabase(ConfigDatabasePath)
}

func initDatabase(path string) (db *sql.DB, err error) {
	// 打开/创建数据库
	db, err = sql.Open("sqlite3", path)
	if err != nil {
		return nil, err
	}

	db.Exec("PRAGMA foreign_keys = ON;")

	// 建立用户表
	DebugLogger.Println("Database: Initializing User")
	_, err = db.Exec(database.CreateUserTable())
	if err != nil {
		ErrorLogger.Println(err.Error())
		return nil, err
	}

	// 建立交易数据表
	DebugLogger.Println("Database: Initializing Transaction")
	_, err = db.Exec(database.CreateTransactionTable())
	if err != nil {
		return nil, err
	}

	// 建立公钥表
	DebugLogger.Println("Database: Initializing CKKS PublicKey")
	_, err = db.Exec(database.CreateCKKSPublicKeyTable())
	if err != nil {
		return nil, err
	}

	DebugLogger.Println("Database: Initializing ECDSA PublicKey")
	_, err = db.Exec(database.CreateECDSAPublicKeyTable())
	if err != nil {
		return nil, err
	}

	// 建立重加密密钥表
	DebugLogger.Println("Database: Initializing CKKS SwitchingKey")
	_, err = db.Exec(database.CreateSwitchingKeyTable())
	if err != nil {
		return nil, err
	}

	return
}
