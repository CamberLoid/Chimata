package clientlib

import (
	"database/sql"
	"os"

	database "github.com/CamberLoid/Chimata/internal/db"
	_ "github.com/mattn/go-sqlite3"
)

const (
	DefaultDatabaseDirPath  string = "/.config/Chimata/"
	DefaultDatabaseFileName string = "client.db"
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
	// 初始化数据库对象
	db, err = sql.Open("sqlite3", path)
	if err != nil {
		return nil, err
	}
	db.Exec("PRAGMA foreign_keys = ON;")

	// 建立用户表
	_, err = db.Exec(database.CreateUserTable())
	if err != nil {
		return nil, err
	}

	// 建立密钥表
	_, err = db.Exec(database.CreateCKKSKeyTable())
	if err != nil {
		return nil, err
	}
	_, err = db.Exec(database.CreateECDSAKeyTable())
	if err != nil {
		return nil, err
	}

	return
}
