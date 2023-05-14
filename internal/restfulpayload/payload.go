package restfulpayload

import "github.com/google/uuid"

// RegisterUserReq 结构体表示了通信中的用户注册请求
// 其中 pubkeys 部分使用 base64 编码
type RegisterUserReq struct {
	UUID         uuid.UUID `json:"uuid"`
	Name         string    `json:"name"`
	CKKS_pubkey  string    `json:"ckks_pubkey"`
	ECDSA_pubkey string    `json:"ecdsa_pubkey"`
}

// RegisterSwkReq 结构体表示了通信中提交 swk 注册请求
// 其中 swk 部分使用 base64 编码
type RegisterSwkReq struct {
	UserIn  uuid.UUID `json:"userIn"`
	UserOut uuid.UUID `json:"userOut"`
	Swk     string    `json:"swk"`
}

// AuditorRegisterUserReq 结构体表示了通信中的用户注册请求
// 和前面不同，这个是用于向监管者提交注册请求的
// 本文假设监管者是绝对可信的
// 其中 pubkeys 和 privkey 部分使用 base64 编码
type AuditorRegisterUserReq struct {
	UUID         uuid.UUID `json:"uuid"`
	Name         string    `json:"name"`
	CKKS_privkey string    `json:"ckks_privkey"`
	ECDSA_pubkey string    `json:"ecdsa_pubkey"`
}
