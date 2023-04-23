package key

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
)

// --- ECDSA 公钥和私钥的 JSON 格式部分 --- //
// Pubkey : {'X': (string), 'Y': (string), 'Curve': (string)}
// Privkey: {'X': (string), 'Y': (string), 'Curve': (string), 'D': (string)}

type ECDSAPubkeyJSON struct {
	X     string `json:"x"`
	Y     string `json:"y"`
	Curve string `json:"curve"`
}

type ECDSAPrivateKeyJSON struct {
	ECDSAPubkeyJSON
	D string `json:"d"`
}

// getCurve 根据 curveName 获取并返回 elliptic.Curve
// 由 ChatGPT 生成
func getCurve(curveName string) (elliptic.Curve, error) {
	switch curveName {
	case "P-224":
		return elliptic.P224(), nil
	case "P-256":
		return elliptic.P256(), nil
	case "P-384":
		return elliptic.P384(), nil
	case "P-521":
		return elliptic.P521(), nil
	default:
		return nil, errors.New("unrecognized elliptic curve")
	}
}

// 将
func EncodeECDSAPubkeyToJson(pubkey *ecdsa.PublicKey) []byte {
	var PubkeyJSON = ECDSAPubkeyJSON{
		X:     pubkey.X.String(),
		Y:     pubkey.Y.String(),
		Curve: pubkey.Params().Name,
	}

	jsonData, _ := json.Marshal(PubkeyJSON)

	return jsonData
}

// DecodeJSONToECDSAPubkey 将 JSON 格式的公钥转换为 ecdsa.PublicKey
func DecodeJSONToECDSAPubkey(jsonData []byte) (pubkey *ecdsa.PublicKey, err error) {
	var PubkeyJSON = new(ECDSAPubkeyJSON)
	err = json.Unmarshal(jsonData, PubkeyJSON)
	if err != nil {
		return nil, err
	}

	curve, err := getCurve(PubkeyJSON.Curve)
	if err != nil {
		return nil, err
	}

	x := new(big.Int)
	y := new(big.Int)

	x, _ = x.SetString(PubkeyJSON.X, 10)
	y, _ = y.SetString(PubkeyJSON.Y, 10)

	pubkey = &ecdsa.PublicKey{
		Curve: curve,
		X:     x,
		Y:     y,
	}

	return
}

func EncodeECDSAPrivateKeyToJson(privkey *ecdsa.PrivateKey) []byte {
	var PrivkeyJSON = new(ECDSAPrivateKeyJSON)

	PrivkeyJSON.Curve = privkey.Params().Name
	PrivkeyJSON.D = privkey.D.String()
	PrivkeyJSON.X = privkey.X.String()
	PrivkeyJSON.Y = privkey.Y.String()

	jsonData, _ := json.Marshal(PrivkeyJSON)

	return jsonData
}

func DecodeJSONToECDSAPrivateKey(jsonData []byte) (privkey *ecdsa.PrivateKey, err error) {
	var PrivkeyJSON = new(ECDSAPrivateKeyJSON)
	err = json.Unmarshal(jsonData, PrivkeyJSON)
	if err != nil {
		return nil, err
	}

	curve, err := getCurve(PrivkeyJSON.Curve)
	if err != nil {
		return nil, err
	}

	x := new(big.Int)
	y := new(big.Int)
	d := new(big.Int)

	x, _ = x.SetString(PrivkeyJSON.X, 10)
	y, _ = y.SetString(PrivkeyJSON.Y, 10)
	d, _ = d.SetString(PrivkeyJSON.D, 10)

	privkey = &ecdsa.PrivateKey{
		PublicKey: ecdsa.PublicKey{
			Curve: curve,
			X:     x,
			Y:     y,
		},
		D: d,
	}

	return
}

func MarshalECDSAPubkeyMap(mp *map[string]any) (pk *ecdsa.PublicKey, err error) {
	// 提取Curve、X和Y的值
	curveName, ok := (*mp)["Curve"].(string)
	if !ok {
		err = fmt.Errorf("Curve field not found or not a string")
		return
	}
	xStr, ok := (*mp)["X"].(string)
	if !ok {
		err = fmt.Errorf("X field not found or not a string")
		return
	}
	yStr, ok := (*mp)["Y"].(string)
	if !ok {
		err = fmt.Errorf("Y field not found or not a string")
		return
	}

	// 将X和Y的值转换为big.Int类型
	x, ok := new(big.Int).SetString(xStr, 10)
	if !ok {
		err = fmt.Errorf("Failed to convert X value to big.Int")
		return
	}
	y, ok := new(big.Int).SetString(yStr, 10)
	if !ok {
		err = fmt.Errorf("Failed to convert Y value to big.Int")
		return
	}

	curve, err := getCurve(curveName)

	if err != nil {
		return
	}

	// 创建新的ecdsa.PublicKey
	pk = &ecdsa.PublicKey{
		Curve: curve,
		X:     x,
		Y:     y,
	}

	return
}
