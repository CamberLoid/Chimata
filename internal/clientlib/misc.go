package clientlib

import (
	"crypto/rand"
	"math/big"
	"reflect"
	"strconv"
)

func getType(myvar interface{}) string {
	return reflect.TypeOf(myvar).Name()
}

func roundToCent(v float64) float64 {
	value, _ := strconv.ParseFloat(strconv.FormatFloat(v, 'f', 2, 64), 64)
	return value
}

func GenRandFloat() float64 {
	randInt, _ := rand.Int(rand.Reader, big.NewInt(1000000))
	randFloat := float64(randInt.Int64()) / 100.0

	return randFloat
}
