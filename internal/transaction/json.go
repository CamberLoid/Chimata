package transaction

import "encoding/json"

func (t Transaction) MarshalToJSON() (res []byte, err error) {
	return json.Marshal(t)
}
