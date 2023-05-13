package main

import (
	"database/sql"
	"log"
	"net/http"
	"os"
)

var (
	CriticalLogger log.Logger
	ErrorLogger    log.Logger
	WarningLogger  log.Logger
	InfoLogger     log.Logger
	DebugLogger    log.Logger
)

var (
	Database *sql.DB
)

const (
	DefaultListenPort = "16001"
	DefaultVersion    = "indev"
	DefaultListenAddr = "127.0.0.1"
)

var (
	ConfigListenAddr              = DefaultListenAddr
	ConfigListenPort              = DefaultListenPort
	isIgnoreValidityOfTransaction = true
	ConfigVersion                 = DefaultVersion
)

func loggerInit() {
	CriticalLogger = *log.New(os.Stderr, "CRITICAL: ", log.Ldate|log.Ltime|log.Lshortfile)
	ErrorLogger = *log.New(os.Stderr, "ERROR: ", log.Ldate|log.Ltime|log.Lshortfile)
	WarningLogger = *log.New(os.Stderr, "WARNING: ", log.Ldate|log.Ltime|log.Lshortfile)
	InfoLogger = *log.New(os.Stdout, "INFO: ", log.Ldate|log.Ltime|log.Lshortfile)
	DebugLogger = *log.New(os.Stdout, "DEBUG: ", log.Ldate|log.Ltime|log.Lshortfile)
}

func main() {
	var err error
	loggerInit()

	InfoLogger.Printf("Project Chimata Server Version %s", ConfigVersion)

	http.HandleFunc("/", HandleNotFound)
	http.HandleFunc("/version", HandlerVersion)

	// 交易部分
	http.HandleFunc("/transaction/create/bySenderPK", HandlerTransactionCreateBySenderPK)
	http.HandleFunc("/transaction/create/byReceiptPK", HandlerTransactionCreateByReceiptPK)
	http.HandleFunc("/transaction/get", HandlerTransactionGet)
	http.HandleFunc("/transaction/confirm", HandlerTransactionConfirm)

	// 用户部分
	http.HandleFunc("/user/getBalance", HandlerUserGetBalance)
	http.HandleFunc("/user/getTransaction", todo)

	http.HandleFunc("/register/user", HandlerRegisterUser)
	http.HandleFunc("/register/swk", HandlerRegisterSwk)

	if Database, err = InitDatabase(); err != nil {
		CriticalLogger.Fatal(err.Error())
	}

	defer Database.Close()

	InfoLogger.Printf("Listening: %v", ConfigListenAddr+":"+ConfigListenPort)
	if err := http.ListenAndServe(ConfigListenAddr+":"+ConfigListenPort, nil); err != nil {
		log.Fatal(err)
	}
}
