package main

import "github.com/tuneinsight/lattigo/v4/ckks"

func GetCKKSParams() ckks.Parameters {
	p, _ := ckks.NewParametersFromLiteral(ckks.PN12QP109)
	return p
}
