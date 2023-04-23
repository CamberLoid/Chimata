package client_lib

// ca.go 包含客户端和 CA 交互用的接口函数等

// Todos:
// - [ ] 请求最新的 CA 认证公钥
//   - [x] SyncCASigningKey
//     - [ ] TestSyncCASigningKey
// - [ ] 请求 CA 向服务端发送 swk
//   进一步：考虑 Time-based swk

import (
	"crypto/ecdsa"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"

	"github.com/CamberLoid/Chimata/internal/key"
	"github.com/tuneinsight/lattigo/v4/rlwe"
)

const (
	// 默认的 CA 接口，测试就用这个了
	DefaultCAUrl string = "http://localhost:16002"
)

const (
	CAPubkeyEndpoint string = "/pubkey"
)

func RequestAuthorize(rlwe.SecretKey, rlwe.PublicKey) ([]string, error) {
	panic("Not implemented yet!")
}

func RequestNewKeyFromCA() (rlwe.SecretKey, rlwe.PublicKey) {
	panic("Not implemented yet!")
}

func SyncCASigningKey() ([]ecdsa.PublicKey, error) {
	return syncCASignPublicKey(DefaultServerURL)
}

func SyncCASigningKeyWithURL(caUrl string) ([]ecdsa.PublicKey, error) {
	if caUrl == "" {
		caUrl = DefaultCAUrl
	}

	// Check if url is a valid URL
	if _, err := url.ParseRequestURI(caUrl); err != nil {
		return nil, err
	}

	return syncCASignPublicKey(caUrl + CAPubkeyEndpoint)
}

// 通过网络，请求 CA 签名公钥。
// 本方法假定只会返回单个公钥
// 返回 Like：
/*
{
	"status": "OK",
	"pubkey": []
}
*/
func syncCASignPublicKey(url string) (pk []ecdsa.PublicKey, err error) {
	var (
		resp     *http.Response
		jsonData map[string]interface{}
	)

	// 考虑增加认证？
	resp, err = http.Get(url)
	defer resp.Body.Close()

	if err != nil {
		return nil, err
	}

	// 对返回 JSON 进行解码
	err = json.NewDecoder(resp.Body).Decode(&jsonData)

	if err != nil {
		return nil, err
	}
	if jsonData["status"] != "OK" {
		return nil, errors.New("status is not OK!")
	}

	pubkeys := jsonData["pubkey"].([]interface{})

	// 如果pubkeys为zero-value，返回错误
	if pubkeys == nil {
		return nil, errors.New("no pubkey found")
	}

	for _, s := range pubkeys {
		_s := s.(map[string]interface{})
		_pk, err := key.MarshalECDSAPubkeyMap(&_s)
		if err != nil {
			return nil, err
		}
		pk = append(pk, *_pk)
	}

	return
}

// 真的要在这个阶段写么
func (u User) AuthSwitchingKey() error {
	panic("Not implemented yet!")
}
