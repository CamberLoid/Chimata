package restfulpayload

import "github.com/google/uuid"

// UserRegisterReq 结构体表示了通信中的用户注册请求
// 其中 pubkeys 部分使用 base64 编码
type UserRegisterReq struct {
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
