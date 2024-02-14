package keygen

import (
	"encoding/json"
	"errors"
	"fmt"

	"github.com/cronokirby/saferith"
	"github.com/taurusgroup/multi-party-sig/internal/jsontools"
	"github.com/taurusgroup/multi-party-sig/internal/round"
	"github.com/taurusgroup/multi-party-sig/internal/types"
	"github.com/taurusgroup/multi-party-sig/pkg/hash"
	"github.com/taurusgroup/multi-party-sig/pkg/math/arith"
	"github.com/taurusgroup/multi-party-sig/pkg/math/curve"
	"github.com/taurusgroup/multi-party-sig/pkg/math/polynomial"
	"github.com/taurusgroup/multi-party-sig/pkg/paillier"
	"github.com/taurusgroup/multi-party-sig/pkg/party"
	"github.com/taurusgroup/multi-party-sig/pkg/pedersen"
	zkfac "github.com/taurusgroup/multi-party-sig/pkg/zk/fac"
	zkmod "github.com/taurusgroup/multi-party-sig/pkg/zk/mod"
	zkprm "github.com/taurusgroup/multi-party-sig/pkg/zk/prm"
	zksch "github.com/taurusgroup/multi-party-sig/pkg/zk/sch"
)

var _ round.Round = (*Kround3)(nil)

type Kround3 struct {
	*Kround2
	// SchnorrCommitments[j] = Aⱼ
	// Commitment for proof of knowledge in the last round
	SchnorrCommitments map[party.ID]*zksch.Commitment // Aⱼ

	VSSSecrets      map[party.ID]*polynomial.Polynomial
	PaillierSecrets map[party.ID]*paillier.SecretKey
}

type Broadcast3 struct {
	round.NormalBroadcastContent
	// RID = RIDᵢ
	RID types.RID
	C   types.RID
	// VSSPolynomial = Fᵢ(X) VSSPolynomial
	VSSPolynomial *polynomial.Exponent
	// SchnorrCommitments = Aᵢ Schnorr commitment for the final confirmation
	SchnorrCommitments *zksch.Commitment
	ElGamalPublic      curve.Point
	// N Paillier and Pedersen N = p•q, p ≡ q ≡ 3 mod 4
	N *saferith.Modulus
	// S = r² mod N
	S *saferith.Nat
	// T = Sˡ mod N
	T *saferith.Nat
	// Decommitment = uᵢ decommitment bytes
	Decommitment hash.Decommitment
}

// StoreBroadcastMessage implements round.BroadcastRound.
//
// - verify length of Schnorr commitments
// - verify degree of VSS polynomial Fⱼ "in-the-exponent"
//   - if keygen, verify Fⱼ(0) != ∞
//   - if refresh, verify Fⱼ(0) == ∞
//
// - validate Paillier
// - validate Pedersen
// - validate commitments.
// - store ridⱼ, Cⱼ, Nⱼ, Sⱼ, Tⱼ, Fⱼ(X), Aⱼ.
func (r *Kround3) StoreBroadcastMessage(msg round.Message) error {
	from := msg.From
	body, ok := msg.Content.(*Broadcast3)
	if !ok || body == nil {
		fmt.Println("kr3.storebroadcastmessage: invalid content")
		return round.ErrInvalidContent
	}

	// check nil
	if body.N == nil || body.S == nil || body.T == nil || body.VSSPolynomial == nil || body.SchnorrCommitments == nil {
		fmt.Println("kr3.storebroadcastmessage: nil field(s) detected")
		return round.ErrNilFields
	}
	// check RID length
	if err := body.RID.Validate(); err != nil {
		fmt.Println("kr3.storebroadcastmessage: wrong rid length")
		return fmt.Errorf("rid: %w", err)
	}
	if err := body.C.Validate(); err != nil {
		fmt.Println("kr3.storebroadcastmessage: chainkey invalid")
		return fmt.Errorf("chainkey: %w", err)
	}
	// check decommitment
	if err := body.Decommitment.Validate(); err != nil {
		fmt.Println("kr3.storebroadcastmessage: decommitment validation failure")
		return err
	}

	// Save all X, VSSCommitments
	VSSPolynomial := body.VSSPolynomial
	// check that the constant coefficient is 0
	// if refresh then the polynomial is constant
	if !(r.VSSSecret.Constant().IsZero() == VSSPolynomial.IsConstant) {
		fmt.Println("kr3.storebroadcastmessage: vss polynomial has incorrect constant")
		return errors.New("vss polynomial has incorrect constant")
	}
	// check deg(Fⱼ) = t
	if VSSPolynomial.Degree() != r.Threshold() {
		fmt.Println("kr3.storebroadcastmessage: vss polynomial has incorrect degree")
		return errors.New("vss polynomial has incorrect degree")
	}

	// Set Paillier
	if err := paillier.ValidateN(body.N); err != nil {
		fmt.Println("kr3.storebroadcastmessage: paillier validateN failure")
		return err
	}

	// Verify Pedersen
	if err := pedersen.ValidateParameters(body.N, body.S, body.T); err != nil {
		fmt.Println("kr3.storebroadcastmessage: pedersen verification failure")
		return err
	}
	// Verify decommit
	if !r.HashForID(from).Decommit(r.Commitments[from], body.Decommitment,
		body.RID, body.C, VSSPolynomial, body.SchnorrCommitments, body.ElGamalPublic, body.N, body.S, body.T) {
		fmt.Println("kr3.StoreBroadcastMessage(): failed to decommit")
		return errors.New("failed to decommit")
	}
	r.RIDs[from] = body.RID
	r.ChainKeys[from] = body.C
	r.Pedersen[from] = pedersen.New(arith.ModulusFromN(body.N), body.S, body.T)
	r.PaillierPublic[from] = paillier.NewPublicKey(body.N)
	r.VSSPolynomials[from] = body.VSSPolynomial
	r.SchnorrCommitments[from] = body.SchnorrCommitments
	r.ElGamalPublic[from] = body.ElGamalPublic

	return nil
}

// VerifyMessage implements round.Round.
func (Kround3) VerifyMessage(round.Message) error { return nil }

// StoreMessage implements round.Round.
func (Kround3) StoreMessage(round.Message) error { return nil }

// Finalize implements round.Round
//
// - set rid = ⊕ⱼ ridⱼ and update hash state
// - prove Nᵢ is Blum
// - prove Pedersen parameters
// - prove Schnorr for all coefficients of fᵢ(X)
//   - if refresh skip constant coefficient
//
// - send proofs and encryption of share for Pⱼ.
func (r *Kround3) Finalize(out []*round.Message) (round.Session, []*round.Message, error) {
	// c = ⊕ⱼ cⱼ
	chainKey := r.PreviousChainKey
	if chainKey == nil {
		chainKey = types.EmptyRID()
		for _, j := range r.PartyIDs() {
			chainKey.XOR(r.ChainKeys[j])
		}
	}
	// RID = ⊕ⱼ RIDⱼ
	rid := types.EmptyRID()
	for _, j := range r.PartyIDs() {
		rid.XOR(r.RIDs[j])
	}

	// temporary hash which does not modify the state
	h := r.Hash()
	_ = h.WriteAny(rid, r.SelfID())

	// Prove N is a blum prime with zkmod
	mod := zkmod.NewProof(h.Clone(), zkmod.Private{
		P:   r.PaillierSecret.P(),
		Q:   r.PaillierSecret.Q(),
		Phi: r.PaillierSecret.Phi(),
	}, zkmod.Public{N: r.PaillierPublic[r.SelfID()].N()}, nil)

	// prove s, t are correct as aux parameters with zkprm
	prm := zkprm.NewProof(zkprm.Private{
		Lambda: r.PedersenSecret,
		Phi:    r.PaillierSecret.Phi(),
		P:      r.PaillierSecret.P(),
		Q:      r.PaillierSecret.Q(),
	}, h.Clone(), zkprm.Public{Aux: r.Pedersen[r.SelfID()]}, nil)

	out = r.BroadcastMessage(out, &Broadcast4{
		Mod: mod,
		Prm: prm,
	})

	// create P2P messages with encrypted shares and zkfac proof
	for _, j := range r.OtherPartyIDs() {
		// Prove that the factors of N are relatively large
		fac := zkfac.NewProof(zkfac.Private{P: r.PaillierSecret.P(), Q: r.PaillierSecret.Q()}, h.Clone(), zkfac.Public{
			N:   r.PaillierPublic[r.SelfID()].N(),
			Aux: r.Pedersen[j],
		})
		// compute fᵢ(j)
		share := r.VSSSecret.Evaluate(j.Scalar(r.Group()))
		// Encrypt share
		C, _ := r.PaillierPublic[j].Enc(curve.MakeInt(share))

		out = r.SendMessage(out, &Message4{
			Share: C,
			Fac:   fac,
		}, j)
	}

	// Write rid to the hash state
	r.UpdateHashState(rid)
	return &Kround4{
		Kround3:  r,
		RID:      rid,
		ChainKey: chainKey,
	}, out, nil
}

// MessageContent implements round.Round.
func (Kround3) MessageContent() round.Content { return nil }

// RoundNumber implements round.Content.
func (Broadcast3) RoundNumber() round.Number { return 3 }

// BroadcastContent implements round.BroadcastRound.
func (r *Kround3) BroadcastContent() round.BroadcastContent {
	return &Broadcast3{
		VSSPolynomial:      polynomial.EmptyExponent(r.Group()),
		SchnorrCommitments: zksch.EmptyCommitment(r.Group()),
		ElGamalPublic:      r.Group().NewPoint(),
	}
}

// Number implements round.Round.
func (Kround3) Number() round.Number { return 3 }

func (r Kround3) MarshalJSON() ([]byte, error) {
	mr3, e := json.Marshal(map[string]interface{}{
		"SchnorrCommitments": r.SchnorrCommitments,
	})
	if e != nil {
		fmt.Println(e)
		return nil, e
	}
	r2, e := json.Marshal(r.Kround2)
	if e != nil {
		fmt.Println(e)
		return nil, e
	}
	return jsontools.JoinJSON(mr3, r2)
}

func (r *Kround3) UnmarshalJSON(j []byte) error {
	var tmp map[string]json.RawMessage
	if err := json.Unmarshal(j, &tmp); err != nil {
		fmt.Println("Failed to unmarshal kr3 @ tmp")
		return err
	}

	var r2 *Kround2
	if err := json.Unmarshal(j, &r2); err != nil {
		fmt.Println("Failed to unmarshal kr3 @ r2")
		return err
	}

	schc := make(map[party.ID]*zksch.Commitment)
	if err := json.Unmarshal(tmp["SchnorrCommitments"], &schc); err != nil {
		fmt.Println("Failed to unmarshal kr3 @ SchnorrCommitments")
		return err
	}
	r.Kround2 = r2
	r.SchnorrCommitments = schc
	return nil
}

func (b Broadcast3) MarshalJSON() ([]byte, error) {
	nb, e := b.N.MarshalBinary()
	if e != nil {
		fmt.Println("Failed to MarshalBinary Broadcast3.N")
		return nil, e
	}
	sb, e := b.S.MarshalBinary()
	if e != nil {
		fmt.Println("Failed to MarshalBinary Broadcast3.S")
		return nil, e
	}
	tb, e := b.T.MarshalBinary()
	if e != nil {
		fmt.Println("Failed to MarshalBinary Broadcast3.T")
		return nil, e
	}
	return json.Marshal(map[string]interface{}{
		"RID":                b.RID,
		"C":                  b.C,
		"VSSPolynomial":      b.VSSPolynomial,
		"SchnorrCommitments": b.SchnorrCommitments,
		"ElGamalPublic":      b.ElGamalPublic,
		"N":                  nb,
		"S":                  sb,
		"T":                  tb,
		"Decommitment":       b.Decommitment,
	})
}

func (b *Broadcast3) UnmarshalJSON(j []byte) error {
	var tmp map[string]json.RawMessage
	if e := json.Unmarshal(j, &tmp); e != nil {
		fmt.Println("Broadcast3 unmarshal failed @ tmp:", e)
		return e
	}

	var rid types.RID
	if e := json.Unmarshal(tmp["RID"], &rid); e != nil {
		fmt.Println("Broadcast3 unmarshal failed @ rid:", e)
		return e
	}

	var c types.RID
	if e := json.Unmarshal(tmp["C"], &c); e != nil {
		fmt.Println("Broadcast3 unmarshal failed @ c:", e)
		return e
	}

	var vss *polynomial.Exponent
	if e := json.Unmarshal(tmp["VSSPolynomial"], &vss); e != nil {
		fmt.Println("Broadcast3 unmarshal failed @ vss:", e)
		return e
	}

	var schc *zksch.Commitment
	if e := json.Unmarshal(tmp["SchnorrCommitments"], &schc); e != nil {
		fmt.Println("Broadcast3 unmarshal failed @ schc:", e)
		return e
	}

	var elg curve.Point
	var elg256k1 curve.Secp256k1Point
	if e := json.Unmarshal(tmp["ElGamalPublic"], &elg256k1); e != nil {
		fmt.Println("Broadcast3 unmarshal failed @ elg:", e)
		return e
	}
	elg = &elg256k1

	var nb []byte
	if e := json.Unmarshal(tmp["N"], &nb); e != nil {
		fmt.Println("Broadcast3 unmarshal failed @ n:", e)
		return e
	}
	n := *&saferith.Modulus{}
	if e := n.UnmarshalBinary(nb); e != nil {
		fmt.Println("UnmarshalBinary failed for Broadcast3.N:", e)
		return e
	}

	var sb []byte
	if e := json.Unmarshal(tmp["S"], &sb); e != nil {
		fmt.Println("Broadcast3 unmarshal failed @ n:", e)
		return e
	}
	s := *&saferith.Modulus{}
	if e := s.UnmarshalBinary(sb); e != nil {
		fmt.Println("UnmarshalBinary failed for Broadcast3.S:", e)
		return e
	}

	var tb []byte
	if e := json.Unmarshal(tmp["T"], &tb); e != nil {
		fmt.Println("Broadcast3 unmarshal failed @ n:", e)
		return e
	}
	t := *&saferith.Modulus{}
	if e := t.UnmarshalBinary(tb); e != nil {
		fmt.Println("UnmarshalBinary failed for Broadcast3.T:", e)
		return e
	}

	var decom hash.Decommitment
	if e := json.Unmarshal(tmp["Decommitment"], &decom); e != nil {
		fmt.Println("Broadcast3 unmarshal failed @ decom:", e)
		return e
	}

	b.RID = rid
	b.C = c
	b.VSSPolynomial = vss
	b.SchnorrCommitments = schc
	b.ElGamalPublic = elg
	b.N = &n
	b.S = s.Nat()
	b.T = t.Nat()
	b.Decommitment = decom
	return nil
}
