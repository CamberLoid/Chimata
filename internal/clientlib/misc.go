package clientlib

import (
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
