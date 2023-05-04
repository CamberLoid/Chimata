package clientlib_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"

	"github.com/CamberLoid/Chimata/internal/clientlib"
	"github.com/CamberLoid/Chimata/internal/key"
	"github.com/CamberLoid/Chimata/internal/users"
	"github.com/google/uuid"
	"github.com/tuneinsight/lattigo/v4/ckks"
)

var (
	userSender  clientlib.User
	userReceipt clientlib.User
)

func makeNewRandomUser(name string) (user clientlib.User) {
	params, _ := ckks.NewParametersFromLiteral(ckks.PN12QP109)
	keygen := ckks.NewKeyGenerator(params)
	user = clientlib.User{
		*users.NewUser(),
		"",
	}
	userCKKSKeyChain := new(key.CKKSKeyChain)
	userCKKSKeyChain.Identifier = uuid.New()
	userCKKSKeyChain.CKKSPrivateKey = keygen.GenSecretKey()
	userCKKSKeyChain.CKKSPublicKey = keygen.GenPublicKey(userCKKSKeyChain.CKKSPrivateKey)
	user.UserCKKSKeyChain = append(userSender.UserCKKSKeyChain, *userCKKSKeyChain)

	userECDSAKeyChain := new(key.ECDSAKeyChain)
	userECDSAKeyChain.Identifier = uuid.New()
	userECDSAKeyChain.ECDSAPrivateKey, _ = ecdsa.GenerateKey(elliptic.P224(), rand.Reader)
	userECDSAKeyChain.ECDSAPublicKey = &userECDSAKeyChain.ECDSAPrivateKey.PublicKey
	user.UserECDSAKeyChain = append(user.UserECDSAKeyChain, *userECDSAKeyChain)

	user.UserName = name

	return
}

func initTestRandomUser() {
	userSender = makeNewRandomUser("Alice")
	userReceipt = makeNewRandomUser("Bob")
}
