package keygen

import (
	"encoding/json"
	"errors"
	"fmt"

	"github.com/taurusgroup/multi-party-sig/internal/jsontools"
	"github.com/taurusgroup/multi-party-sig/internal/round"
	sch "github.com/taurusgroup/multi-party-sig/pkg/zk/sch"
	"github.com/taurusgroup/multi-party-sig/protocols/cmp/config"
)

var _ round.Round = (*Kround5)(nil)

type Kround5 struct {
	*Kround4
	UpdatedConfig *config.Config
}

type Broadcast5 struct {
	round.NormalBroadcastContent
	// SchnorrResponse is the Schnorr proof of knowledge of the new secret share
	SchnorrResponse *sch.Response
}

// StoreBroadcastMessage implements round.BroadcastRound.
//
// - verify all Schnorr proof for the new ecdsa share.
func (r *Kround5) StoreBroadcastMessage(msg round.Message) error {
	from := msg.From
	body, ok := msg.Content.(*Broadcast5)
	if !ok || body == nil {
		fmt.Println("Kr5.StoreBroadcastMessage(): invalid content")
		return round.ErrInvalidContent
	}

	if !body.SchnorrResponse.IsValid() {
		fmt.Println("Kr5.StoreBroadcastMessage(): schnorrResponse invalid")
		return round.ErrNilFields
	}

	if !body.SchnorrResponse.Verify(r.HashForID(from),
		r.UpdatedConfig.Public[from].ECDSA,
		r.SchnorrCommitments[from], nil) {
		fmt.Println("Kr5.StoreBroadcastMessage(): failed to validate schnorr proof for received share")
		return errors.New("failed to validate schnorr proof for received share")
	}
	return nil
}

// VerifyMessage implements round.Round.
func (Kround5) VerifyMessage(round.Message) error { return nil }

// StoreMessage implements round.Round.
func (r *Kround5) StoreMessage(round.Message) error { return nil }

// Finalize implements round.Round.
func (r *Kround5) Finalize([]*round.Message) (round.Session, []*round.Message, error) {
	return r.ResultRound(r.UpdatedConfig), nil, nil
}

// MessageContent implements round.Round.
func (r *Kround5) MessageContent() round.Content { return nil }

// RoundNumber implements round.Content.
func (Broadcast5) RoundNumber() round.Number { return 5 }

// BroadcastContent implements round.BroadcastRound.
func (r *Kround5) BroadcastContent() round.BroadcastContent {
	return &Broadcast5{
		SchnorrResponse: sch.EmptyResponse(r.Group()),
	}
}

// Number implements round.Round.
func (Kround5) Number() round.Number { return 5 }

func (r Kround5) MarshalJSON() ([]byte, error) {
	mr5, e := json.Marshal(map[string]interface{}{
		"UpdatedConfig": r.UpdatedConfig,
	})
	if e != nil {
		fmt.Println(e)
		return nil, e
	}
	r4, e := json.Marshal(r.Kround4)
	if e != nil {
		fmt.Println(e)
		return nil, e
	}
	return jsontools.JoinJSON(mr5, r4)
}

func (r *Kround5) UnmarshalJSON(j []byte) error {
	var tmp map[string]json.RawMessage
	if err := json.Unmarshal(j, &tmp); err != nil {
		return err
	}

	var r4 Kround4
	if err := json.Unmarshal(j, &r4); err != nil {
		return err
	}

	upc := config.Config{}
	if err := json.Unmarshal(tmp["UpdatedConfig"], &upc); err != nil {
		return err
	}
	r.Kround4 = &r4
	r.UpdatedConfig = &upc
	return nil
}

func (m Broadcast5) MarshalJSON() ([]byte, error) {
	return json.Marshal(map[string]interface{}{
		"SchnorrResponse": m.SchnorrResponse,
	})
}

func (m *Broadcast5) UnmarshalJSON(j []byte) error {
	var tmp map[string]json.RawMessage
	if e := json.Unmarshal(j, &tmp); e != nil {
		fmt.Println("Broadcast5 unmarshal failed @ tmp:", e)
		return e
	}

	var schr *sch.Response
	if e := json.Unmarshal(tmp["SchnorrResponse"], &schr); e != nil {
		fmt.Println("Broadcast5 unmarshal failed @ schr:", e)
		return e
	}

	m.SchnorrResponse = schr
	return nil
}
