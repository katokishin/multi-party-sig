package sign

import (
	"encoding/json"
	"errors"
	"fmt"

	"github.com/taurusgroup/multi-party-sig/internal/jsontools"
	"github.com/taurusgroup/multi-party-sig/internal/round"
	"github.com/taurusgroup/multi-party-sig/pkg/math/curve"
	"github.com/taurusgroup/multi-party-sig/pkg/party"
	zklogstar "github.com/taurusgroup/multi-party-sig/pkg/zk/logstar"
)

var _ round.Round = (*Sround4)(nil)

type Sround4 struct {
	*Sround3
	// DeltaShares[j] = δⱼ
	DeltaShares map[party.ID]curve.Scalar

	// BigDeltaShares[j] = Δⱼ = [kⱼ]•Γⱼ
	BigDeltaShares map[party.ID]curve.Point

	// Gamma = ∑ᵢ Γᵢ
	Gamma curve.Point

	// ChiShare = χᵢ
	ChiShare curve.Scalar
}

type Message4 struct {
	ProofLog *zklogstar.Proof
}

type Broadcast4 struct {
	round.NormalBroadcastContent
	// DeltaShare = δⱼ
	DeltaShare curve.Scalar
	// BigDeltaShare = Δⱼ = [kⱼ]•Γⱼ
	BigDeltaShare curve.Point
}

// StoreBroadcastMessage implements round.BroadcastRound.
//
// - store δⱼ, Δⱼ
func (r *Sround4) StoreBroadcastMessage(msg round.Message) error {
	body, ok := msg.Content.(*Broadcast4)
	if !ok || body == nil {
		return round.ErrInvalidContent
	}
	if body.DeltaShare.IsZero() || body.BigDeltaShare.IsIdentity() {
		return round.ErrNilFields
	}
	r.BigDeltaShares[msg.From] = body.BigDeltaShare
	r.DeltaShares[msg.From] = body.DeltaShare
	return nil
}

// VerifyMessage implements round.Round.
//
// - Verify Π(log*)(ϕ”ᵢⱼ, Δⱼ, Γ).
func (r *Sround4) VerifyMessage(msg round.Message) error {
	from, to := msg.From, msg.To
	body, ok := msg.Content.(*Message4)
	if !ok || body == nil {
		return round.ErrInvalidContent
	}

	zkLogPublic := zklogstar.Public{
		C:      r.K[from],
		X:      r.BigDeltaShares[from],
		G:      r.Gamma,
		Prover: r.Paillier[from],
		Aux:    r.Pedersen[to],
	}
	if !body.ProofLog.Verify(r.HashForID(from), zkLogPublic) {
		return errors.New("failed to validate log proof")
	}

	return nil
}

// StoreMessage implements round.Round.
func (Sround4) StoreMessage(round.Message) error {
	return nil
}

// Finalize implements round.Round
//
// - set δ = ∑ⱼ δⱼ
// - set Δ = ∑ⱼ Δⱼ
// - verify Δ = [δ]G
// - compute σᵢ = rχᵢ + kᵢm.
func (r *Sround4) Finalize(out []*round.Message) (round.Session, []*round.Message, error) {
	// δ = ∑ⱼ δⱼ
	// Δ = ∑ⱼ Δⱼ
	Delta := r.Group().NewScalar()
	BigDelta := r.Group().NewPoint()
	for _, j := range r.PartyIDs() {
		Delta.Add(r.DeltaShares[j])
		BigDelta = BigDelta.Add(r.BigDeltaShares[j])
	}

	// Δ == [δ]G
	deltaComputed := Delta.ActOnBase()
	if !deltaComputed.Equal(BigDelta) {
		return r.AbortRound(errors.New("computed Δ is inconsistent with [δ]G")), nil, nil
	}

	deltaInv := r.Group().NewScalar().Set(Delta).Invert() // δ⁻¹
	BigR := deltaInv.Act(r.Gamma)                         // R = [δ⁻¹] Γ
	R := BigR.XScalar()                                   // r = R|ₓ

	// km = Hash(m)⋅kᵢ
	km := curve.FromHash(r.Group(), r.Message)
	km.Mul(r.KShare)

	// σᵢ = rχᵢ + kᵢm
	SigmaShare := r.Group().NewScalar().Set(R).Mul(r.ChiShare).Add(km)

	// Send to all
	out = r.BroadcastMessage(out, &Broadcast5{SigmaShare: SigmaShare})
	return &Sround5{
		Sround4:     r,
		SigmaShares: map[party.ID]curve.Scalar{r.SelfID(): SigmaShare},
		Delta:       Delta,
		BigDelta:    BigDelta,
		BigR:        BigR,
		R:           R,
	}, out, nil
}

// RoundNumber implements round.Content.
func (Message4) RoundNumber() round.Number { return 4 }

// MessageContent implements round.Round.
func (r *Sround4) MessageContent() round.Content {
	return &Message4{
		ProofLog: zklogstar.Empty(r.Group()),
	}
}

// RoundNumber implements round.Content.
func (Broadcast4) RoundNumber() round.Number { return 4 }

// BroadcastContent implements round.BroadcastRound.
func (r *Sround4) BroadcastContent() round.BroadcastContent {
	return &Broadcast4{
		DeltaShare:    r.Group().NewScalar(),
		BigDeltaShare: r.Group().NewPoint(),
	}
}

// Number implements round.Round.
func (Sround4) Number() round.Number { return 4 }

func (r *Sround4) MarshalJSON() ([]byte, error) {
	r4, e := json.Marshal(map[string]interface{}{
		"DeltaShares":    r.DeltaShares,
		"BigDeltaShares": r.BigDeltaShares,
		"Gamma":          r.Gamma,
		"ChiShare":       r.ChiShare,
	})
	if e != nil {
		fmt.Println("sr4 marshal failed @ r4:", e)
		return nil, e
	}

	r3, e := json.Marshal(r.Sround3)
	if e != nil {
		fmt.Println("sr4 marshal failed @ r3:", e)
		return nil, e
	}

	return jsontools.JoinJSON(r4, r3)
}

func (r *Sround4) UnmarshalJSON(j []byte) error {
	var tmp map[string]json.RawMessage
	if err := json.Unmarshal(j, &tmp); err != nil {
		return err
	}

	var r3 *Sround3
	if e := json.Unmarshal(j, &r3); e != nil {
		fmt.Println("sr4 unmarshal failed @ r3:", e)
		return e
	}

	deltas := make(map[party.ID]curve.Scalar)
	deltas256k1 := make(map[party.ID]curve.Secp256k1Scalar)
	if e := json.Unmarshal(tmp["DeltaShares"], &deltas256k1); e != nil {
		fmt.Println("sr4 unmarshal failed @ deltashares:", e)
		return e
	}
	for k, v := range deltas256k1 {
		v := v
		deltas[k] = &v
	}

	bigdeltas := make(map[party.ID]curve.Point)
	bigdeltas256k1 := make(map[party.ID]curve.Secp256k1Point)
	if e := json.Unmarshal(tmp["BigDeltaShares"], &bigdeltas256k1); e != nil {
		fmt.Println("sr4 unmarshal failed @ bigdeltashares:", e)
		return e
	}
	for k, v := range bigdeltas256k1 {
		v := v
		bigdeltas[k] = &v
	}

	var gp curve.Point
	var gp256k1 curve.Secp256k1Point
	if e := json.Unmarshal(tmp["Gamma"], &gp256k1); e != nil {
		fmt.Println("sr4 unmarshal failed @ gamma:", e)
		return e
	}
	gp = &gp256k1

	var cs curve.Scalar
	var cs256k1 curve.Secp256k1Scalar
	if e := json.Unmarshal(tmp["ChiShare"], &cs256k1); e != nil {
		fmt.Println("sr4 unmarshal failed @ chishare:", e)
		return e
	}
	cs = &cs256k1

	r.Sround3 = r3
	r.DeltaShares = deltas
	r.BigDeltaShares = bigdeltas
	r.Gamma = gp
	r.ChiShare = cs
	return nil
}
