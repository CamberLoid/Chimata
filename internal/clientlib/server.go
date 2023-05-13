// server.go 包括客户端与服务端交互的接口和函数

package clientlib

import (
	"bytes"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"

	"github.com/CamberLoid/Chimata/internal/restfulpayload"
	"github.com/CamberLoid/Chimata/internal/transaction"
	"github.com/google/uuid"
	"github.com/tuneinsight/lattigo/v4/rlwe"
)

const (
	DefaultServerURL           string = "http://127.0.0.1:16001"
	TransactionCreateEndpoint  string = "/transaction/create"
	TransactionConfirmEndpoint string = "/transaction/confirm"
	TransactionGetEndpoint     string = "/transaction/get"
	GetBalanceEndpoint         string = "/user/getBalance"
	RegisterUserEndpoint       string = "/register/user"
	RegisterSwkEndpoint        string = "/register/swk"
)

var (
	ConfigServerURL string = DefaultServerURL
)

type HTTPRequestJSON struct {
	OAuth string                 `json:"oauth"`
	Body  map[string]interface{} `json:"body"`
}

type GetBalanceJSON struct {
	UserUUID [16]byte `json:"useruuid"`
}

// --- 注册部分 ---

func (u *User) RegisterUser() error {
	request := new(restfulpayload.UserRegisterReq)
	var err error
	if len(u.UserIdentifier) == 0 {
		u.UserIdentifier = uuid.New()
	}
	request.UUID = u.UserIdentifier
	request.Name = u.UserName
	pk, err := u.UserCKKSKeyChain[0].CKKSPublicKey.MarshalBinary()
	if err != nil {
		return err
	}
	request.CKKS_pubkey = base64.RawStdEncoding.EncodeToString(pk)
	epk, err := x509.MarshalPKIXPublicKey(u.UserECDSAKeyChain[0].ECDSAPublicKey)
	if err != nil {
		return err
	}
	request.ECDSA_pubkey = base64.RawStdEncoding.EncodeToString(epk)

	jsonBytes, err := json.Marshal(request)
	if err != nil {
		return err
	}
	resp, err := http.Post(ConfigServerURL+RegisterUserEndpoint, "application/json", bytes.NewBuffer(jsonBytes))
	if err != nil {
		return err
	}
	if resp.Status != "200 OK" {
		return fmt.Errorf("returned " + resp.Status)
	}

	return nil
}

func RegisterSwk(userIn, userOut uuid.UUID, swk *rlwe.SwitchingKey) error {
	req := new(restfulpayload.RegisterSwkReq)
	swkBytes, err := swk.MarshalBinary()
	if err != nil {
		return err
	}
	swkBase64 := base64.RawStdEncoding.EncodeToString(swkBytes)

	// Form payload
	req.UserIn = userIn
	req.UserOut = userOut
	req.Swk = swkBase64

	jsonBytes, err := json.Marshal(req)
	if err != nil {
		return err
	}
	resp, err := http.Post(ConfigServerURL+RegisterSwkEndpoint, "application/json", bytes.NewBuffer(jsonBytes))
	if err != nil {
		return err
	}
	if resp.Status != "200 OK" {
		return fmt.Errorf("returned " + resp.Status)
	}

	return nil
}

// --- 创建交易部分 ---

// 调用 createTransferJob 进行进一步动作。
// createTransferJob 基于 HTTP POST 进行转账请求的发起，将编码后的转账请求发送到服务端；
// 服务端将转账请求存入数据库，并返回转账任务的 UUID/流水号
func (u *User) CreateTransferJob(transaction *transaction.Transaction) (newT *transaction.Transaction, err error) {
	// 检查 ConfigServerURL 是否合法，如果不合法，则返回错误
	// 否则，将 ConfigServerURL 设置为默认值
	if _, err := url.ParseRequestURI(ConfigServerURL); err != nil {
		ConfigServerURL = DefaultServerURL
	}

	return u.createTransferJob(transaction, ConfigServerURL+TransactionCreateEndpoint)
}

// createTransferJob 基于 HTTP POST 进行转账请求的发起，将编码后的转账请求发送到服务端；
// 服务端将转账请求存入数据库，并返回转账任务的 UUID/流水号
// 输入：转账结构体，服务端地址
// 输出：新的转账结构体的指针，错误
func (u *User) createTransferJob(t *transaction.Transaction, server string) (newT *transaction.Transaction, err error) {

	// 将交易信息整理成 JSON 格式
	// 交易信息包括：发送者的 UUID，接收者的 UUID，加密后的金额，签名
	payload, err := json.Marshal(t.CopyToJSONStruct())
	if err != nil {
		return nil, err
	}

	if len(t.CTSender) != 0 {
		server = server + "/bySenderPK"
	} else if len(t.CTReceipt) != 0 {
		server = server + "/byReceiptPK"
	} else {
		return nil, errors.New("invalid transaction")
	}

	// 将 JSON 格式的交易信息发送到服务端
	resp, err := http.Post(server, "application/json", bytes.NewBuffer(payload))
	defer resp.Body.Close()

	if err != nil {
		return nil, err
	}

	newT, err = UnmarshalTransactionFromResponse(resp)

	return
}

// CreateReceiveTask 创建一个接受任务，提交至云端，并将接受任务的 UUID/流水号返回
// 目前不考虑
func (u *User) CreateReceiveJob(target User) error {
	return errors.New("not implemented yet")
}

// ServerGetBalance 从服务端获取用户的余额密文。一个更优雅的方法是调用 User.ServerGetBalance()。
// 一个可能返回的json：
// "status": "OK", "Failed"
// "balance" : rlwe.ciphertext
func ServerGetBalance(server string, target uuid.UUID) (balance *rlwe.Ciphertext, err error) {
	var (
		jsonData map[string]interface{}
	)

	server, err = url.JoinPath(server, GetBalanceEndpoint)
	if err != nil {
		return nil, err
	}

	payload, err := json.Marshal(GetBalanceJSON{UserUUID: target})
	if err != nil {
		return nil, err
	}

	resp, err := http.NewRequest("GET", server, bytes.NewBuffer(payload))

	if err != nil {
		return nil, err
	}

	err = json.NewDecoder(resp.Body).Decode(&jsonData)
	if err != nil {
		return nil, err
	}

	if err = CheckIfOK(jsonData); err != nil {
		return nil, err
	}

	balanceString := jsonData["balance"].(string)
	if balanceString == "" {
		return nil, errors.New("balance not found")
	}

	balance = new(rlwe.Ciphertext)
	balanceBytes, err := base64.StdEncoding.DecodeString(balanceString)
	if err != nil {
		return nil, err
	}
	err = balance.UnmarshalBinary(balanceBytes)

	return
}

// --- 接受转账 （Accept Transaction）部分 ---

// CreateConfirmTransactionTask 用来将确认交易信息上传到服务端
// 输入：Transaction 结构体
// 不会有返回值
func (u User) CreateConfirmTransactionTask(t *transaction.Transaction) error {
	payload, err := json.Marshal(t)
	if err != nil {
		return err
	}
	server, err := url.JoinPath(ConfigServerURL, TransactionConfirmEndpoint)
	if err != nil {
		return err
	}

	resp, err := http.Post(server, "application/json", bytes.NewBuffer(payload))
	if err != nil {
		return err
	}

	var jsonData map[string]interface{}
	err = json.NewDecoder(resp.Body).Decode(&jsonData)
	if err != nil {
		return err
	}

	if jsonData["status"].(string) != "OK" {
		return errors.New("status is not ok " + jsonData["err"].(string))
	}
	return nil
}

// --- 获取交易信息部分 ---

func GetTransactionFromServer(id uuid.UUID) (tx *transaction.Transaction, err error) {
	// TODO: 检查url是否合法
	return getTransactionFromServer(ConfigServerURL, id)
}

func getTransactionFromServer(server string, id uuid.UUID) (tx *transaction.Transaction, err error) {
	var (
		jsonData map[string]interface{}
	)

	server, err = url.JoinPath(server, TransactionGetEndpoint)
	if err != nil {
		return nil, err
	}

	payload, err := json.Marshal(*tx)
	if err != nil {
		return nil, err
	}

	resp, err := http.NewRequest("GET", server, bytes.NewBuffer(payload))

	if err != nil {
		return nil, err
	}

	err = json.NewDecoder(resp.Body).Decode(&jsonData)
	if err != nil {
		return nil, err
	}

	if err = CheckIfOK(jsonData); err != nil {
		return nil, err
	}

	tx, err = ExtractTransactionFromResponseJSON(jsonData)

	return
}

// --- Helper Func 部分 ---

func ExtractTransactionFromResponseJSON(jsonData map[string]interface{}) (tx *transaction.Transaction, err error) {
	if jsonData["status"].(string) != "OK" {
		return nil, errors.New(jsonData["err"].(string))
	}

	var newT *transaction.Transaction
	err = json.Unmarshal([]byte(jsonData["transaction"].(string)), newT)
	if err != nil {
		return nil, err
	}

	return newT, nil
}

// 判断服务端返回的json是否是成功的
func CheckIfOK(jsonData map[string]interface{}) (err error) {
	switch s := jsonData["status"].(string); s {
	case "OK":
		return nil
	case "failed", "Failed", "FAILED":
		return errors.New(jsonData["err"].(string))
	default:
		return nil
	}
}

func UnmarshalTransactionFromResponse(resp *http.Response) (*transaction.Transaction, error) {
	var respJSON map[string]interface{}
	newT := new(transaction.TransactionJSON)
	err := json.NewDecoder(resp.Body).Decode(&respJSON)
	if err != nil {
		return nil, err
	}

	if respJSON["status"].(string) != "OK" {
		return nil, errors.New(respJSON["err"].(string))
	}

	outer := respJSON["transaction"].(map[string]interface{})
	outerJSON, _ := json.Marshal(outer)
	err = json.Unmarshal(outerJSON, newT)

	if err != nil {
		return nil, err
	}
	return newT.CopyToStruct()
}
