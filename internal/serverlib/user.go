package serverlib

import (
	"github.com/CamberLoid/Chimata/internal/users"
	"github.com/tuneinsight/lattigo/v4/rlwe"
)

// 不同于客户端，服务端只能看到用户的公钥，以及用户的余额密文
type User struct {
	users.User

	Balance *rlwe.Ciphertext
}
