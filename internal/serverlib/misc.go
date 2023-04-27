package serverlib

import "fmt"

func Recover(f func()) (err error) {
	defer func() {
		if p := recover(); p != nil {
			err = fmt.Errorf("%v", p)
		}
	}()
	f()
	return nil
}
