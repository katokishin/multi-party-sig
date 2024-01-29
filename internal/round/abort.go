package round

import (
	"encoding/json"

	"github.com/taurusgroup/multi-party-sig/pkg/party"
)

// Abort is an empty round containing a list of parties who misbehaved.
type Abort struct {
	*Helper
	Culprits []party.ID
	Err      error
}

func (Abort) VerifyMessage(Message) error                         { return nil }
func (Abort) StoreMessage(Message) error                          { return nil }
func (r *Abort) Finalize([]*Message) (Session, []*Message, error) { return r, nil, nil }
func (Abort) MessageContent() Content                             { return nil }
func (Abort) Number() Number                                      { return 0 }

func (r Abort) UnmarshalJSON(j []byte) error {
	var tmp map[string]json.RawMessage
	if err := json.Unmarshal(j, &tmp); err != nil {
		return err
	}

	var hpr *Helper
	if err := json.Unmarshal(tmp["Helper"], &hpr); err != nil {
		return err
	}

	var cps []party.ID
	if err := json.Unmarshal(tmp["Culprits"], &cps); err != nil {
		return err
	}

	var e *error
	if err := json.Unmarshal(tmp["Err"], &e); err != nil {
		return err
	}

	r.Helper = hpr
	r.Culprits = cps
	r.Err = *e
	return nil
}
