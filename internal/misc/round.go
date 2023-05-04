package misc

import "strconv"

func CKKSMsgRound(v float64) float64 {
	value, _ := strconv.ParseFloat(strconv.FormatFloat(v, 'f', 2, 64), 64)
	return value
}
