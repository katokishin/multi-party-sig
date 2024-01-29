package round

import "encoding/json"

// Output is an empty round containing the output of the protocol.
type Output struct {
	*Helper
	Result interface{}
}

func (Output) VerifyMessage(Message) error                         { return nil }
func (Output) StoreMessage(Message) error                          { return nil }
func (r *Output) Finalize([]*Message) (Session, []*Message, error) { return r, nil, nil }
func (Output) MessageContent() Content                             { return nil }
func (Output) Number() Number                                      { return 0 }

func (r Output) UnmarshalJSON(j []byte) error {
	var tmp map[string]json.RawMessage
	if err := json.Unmarshal(j, &tmp); err != nil {
		return err
	}

	var hpr *Helper
	if err := json.Unmarshal(tmp["Helper"], &hpr); err != nil {
		return err
	}

	var res interface{}
	if err := json.Unmarshal(tmp["Result"], &res); err != nil {
		return err
	}

	r.Helper = hpr
	r.Result = res
	return nil
}
