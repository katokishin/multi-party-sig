package sign

import (
	"encoding/json"
	"errors"
	"fmt"

	"github.com/taurusgroup/multi-party-sig/internal/jsontools"
	"github.com/taurusgroup/multi-party-sig/internal/round"
	"github.com/taurusgroup/multi-party-sig/pkg/ecdsa"
	"github.com/taurusgroup/multi-party-sig/pkg/math/curve"
	"github.com/taurusgroup/multi-party-sig/pkg/party"
)

var _ round.Round = (*Sround5)(nil)

type Sround5 struct {
	*Sround4

	// SigmaShares[j] = σⱼ = m⋅kⱼ + χⱼ⋅R|ₓ
	SigmaShares map[party.ID]curve.Scalar

	// Delta = δ = ∑ⱼ δⱼ
	// computed from received shares
	Delta curve.Scalar

	// BigDelta = Δ = ∑ⱼ Δⱼ
	BigDelta curve.Point

	// R = [δ⁻¹] Γ
	BigR curve.Point

	// R = R|ₓ
	R curve.Scalar
}

type broadcast5 struct {
	round.NormalBroadcastContent
	SigmaShare curve.Scalar
}

// StoreBroadcastMessage implements round.BroadcastRound.
//
// - save σⱼ
func (r *Sround5) StoreBroadcastMessage(msg round.Message) error {
	body, ok := msg.Content.(*broadcast5)
	if !ok || body == nil {
		return round.ErrInvalidContent
	}

	if body.SigmaShare.IsZero() {
		return round.ErrNilFields
	}

	r.SigmaShares[msg.From] = body.SigmaShare
	return nil
}

// VerifyMessage implements round.Round.
func (Sround5) VerifyMessage(round.Message) error { return nil }

// StoreMessage implements round.Round.
func (Sround5) StoreMessage(round.Message) error { return nil }

// Finalize implements round.Round
//
// - compute σ = ∑ⱼ σⱼ
// - verify signature.
func (r *Sround5) Finalize([]*round.Message) (round.Session, []*round.Message, error) {
	// compute σ = ∑ⱼ σⱼ
	Sigma := r.Group().NewScalar()
	for _, j := range r.PartyIDs() {
		Sigma.Add(r.SigmaShares[j])
	}

	signature := &ecdsa.Signature{
		R: r.BigR,
		S: Sigma,
	}

	if !signature.Verify(r.PublicKey, r.Message) {
		return r.AbortRound(errors.New("failed to validate signature")), nil, nil
	}

	return r.ResultRound(signature), nil, nil
}

// MessageContent implements round.Round.
func (r *Sround5) MessageContent() round.Content { return nil }

// RoundNumber implements round.Content.
func (broadcast5) RoundNumber() round.Number { return 5 }

// BroadcastContent implements round.BroadcastRound.
func (r *Sround5) BroadcastContent() round.BroadcastContent {
	return &broadcast5{
		SigmaShare: r.Group().NewScalar(),
	}
}

// Number implements round.Round.
func (Sround5) Number() round.Number { return 5 }

func (r *Sround5) MarshalJSON() ([]byte, error) {
	r5, e := json.Marshal(map[string]interface{}{
		"SigmaShares": r.SigmaShares,
		"Delta":       r.Delta,
		"BigDelta":    r.BigDelta,
		"BigR":        r.BigR,
		"R":           r.R,
	})
	if e != nil {
		fmt.Println("sr5 marshal failed @ r5:", e)
		return nil, e
	}

	r4, e := json.Marshal(r.Sround4)
	if e != nil {
		fmt.Println("sr5 marshal failed @ r4:", e)
		return nil, e
	}

	return jsontools.JoinJSON(r5, r4)
}

func (r *Sround5) UnmarshalJSON(j []byte) error {
	var tmp map[string]json.RawMessage
	if err := json.Unmarshal(j, &tmp); err != nil {
		return err
	}

	var r4 *Sround4
	if err := json.Unmarshal(j, &r4); err != nil {
		fmt.Println("sr5 unmarshal failed @ r4:", err)
		return err
	}

	ssmap := make(map[party.ID]curve.Scalar)
	ssmap256k1 := make(map[party.ID]curve.Secp256k1Scalar)
	if err := json.Unmarshal(tmp["SigmaShares"], &ssmap256k1); err != nil {
		fmt.Println("sr5 unmarshal failed @ sigmashares:", err)
		return err
	}
	for k, v := range ssmap256k1 {
		v := v
		ssmap[k] = &v
	}

	var delta curve.Scalar
	var delta256k1 curve.Secp256k1Scalar
	if err := json.Unmarshal(tmp["Delta"], &delta256k1); err != nil {
		fmt.Println("sr5 unmarshal failed @ delta:", err)
		return err
	}
	delta = &delta256k1

	var bigdelta curve.Point
	var bigdelta256k1 curve.Secp256k1Point
	if err := json.Unmarshal(tmp["BigDelta"], &bigdelta256k1); err != nil {
		fmt.Println("sr5 unmarshal failed @ bigdelta:", err)
		return err
	}
	bigdelta = &bigdelta256k1

	var bigr curve.Point
	var bigr256k1 curve.Secp256k1Point
	if err := json.Unmarshal(tmp["BigR"], &bigr256k1); err != nil {
		fmt.Println("sr5 unmarshal failed @ bigr:", err)
		return err
	}
	bigr = &bigr256k1

	var rv curve.Scalar
	var r256k1 curve.Secp256k1Scalar
	if err := json.Unmarshal(tmp["R"], &r256k1); err != nil {
		fmt.Println("sr5 unmarshal failed @ r:", err)
		return err
	}
	rv = &r256k1

	r.Sround4 = r4
	r.SigmaShares = ssmap
	r.Delta = delta
	r.BigDelta = bigdelta
	r.BigR = bigr
	r.R = rv
	return nil
}
