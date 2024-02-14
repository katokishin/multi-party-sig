package keygen

import (
	"encoding/base64"
	"encoding/json"
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
	zksch "github.com/taurusgroup/multi-party-sig/pkg/zk/sch"
)

var _ round.Round = (*Kround2)(nil)

type Kround2 struct {
	*Kround1

	// VSSPolynomials[j] = Fⱼ(X) = fⱼ(X)•G
	VSSPolynomials map[party.ID]*polynomial.Exponent

	// Commitments[j] = H(Keygen3ⱼ ∥ Decommitments[j])
	Commitments map[party.ID]hash.Commitment

	// RIDs[j] = ridⱼ
	RIDs map[party.ID]types.RID
	// ChainKeys[j] = cⱼ
	ChainKeys map[party.ID]types.RID

	// ShareReceived[j] = xʲᵢ
	// share received from party j
	ShareReceived map[party.ID]curve.Scalar

	ElGamalPublic map[party.ID]curve.Point
	// PaillierPublic[j] = Nⱼ
	PaillierPublic map[party.ID]*paillier.PublicKey

	// Pedersen[j] = (Nⱼ,Sⱼ,Tⱼ)
	Pedersen map[party.ID]*pedersen.Parameters

	ElGamalSecret curve.Scalar

	// PaillierSecret = (pᵢ, qᵢ)
	PaillierSecret *paillier.SecretKey

	// PedersenSecret = λᵢ
	// Used to generate the Pedersen parameters
	PedersenSecret *saferith.Nat

	// SchnorrRand = aᵢ
	// Randomness used to compute Schnorr commitment of proof of knowledge of secret share
	SchnorrRand *zksch.Randomness

	// Decommitment for Keygen3ᵢ
	Decommitment hash.Decommitment // uᵢ
}

type Broadcast2 struct {
	round.ReliableBroadcastContent
	// Commitment = Vᵢ = H(ρᵢ, Fᵢ(X), Aᵢ, Yᵢ, Nᵢ, sᵢ, tᵢ, uᵢ)
	Commitment hash.Commitment
}

// StoreBroadcastMessage implements round.BroadcastRound.
// - save commitment Vⱼ.
func (r *Kround2) StoreBroadcastMessage(msg round.Message) error {
	body, ok := msg.Content.(*Broadcast2)
	if !ok || body == nil {
		return round.ErrInvalidContent
	}
	if err := body.Commitment.Validate(); err != nil {
		return err
	}
	r.Commitments[msg.From] = body.Commitment
	return nil
}

// VerifyMessage implements round.Round.
func (Kround2) VerifyMessage(round.Message) error { return nil }

// StoreMessage implements round.Round.
func (Kround2) StoreMessage(round.Message) error { return nil }

// Finalize implements round.Round
//
// - send all committed data.
func (r *Kround2) Finalize(out []*round.Message) (round.Session, []*round.Message, error) {
	// Send the message we created in Round1 to all
	out = r.BroadcastMessage(out, &Broadcast3{
		RID:                r.RIDs[r.SelfID()],
		C:                  r.ChainKeys[r.SelfID()],
		VSSPolynomial:      r.VSSPolynomials[r.SelfID()],
		SchnorrCommitments: r.SchnorrRand.Commitment(),
		ElGamalPublic:      r.ElGamalPublic[r.SelfID()],
		N:                  r.Pedersen[r.SelfID()].N(),
		S:                  r.Pedersen[r.SelfID()].S(),
		T:                  r.Pedersen[r.SelfID()].T(),
		Decommitment:       r.Decommitment,
	})
	return &Kround3{
		Kround2:            r,
		SchnorrCommitments: map[party.ID]*zksch.Commitment{},
	}, out, nil
}

// PreviousRound implements round.Round.
func (r *Kround2) PreviousRound() round.Round { return r.Kround1 }

// MessageContent implements round.Round.
func (Kround2) MessageContent() round.Content { return nil }

// RoundNumber implements round.Content.
func (Broadcast2) RoundNumber() round.Number { return 2 }

// BroadcastContent implements round.BroadcastRound.
func (Kround2) BroadcastContent() round.BroadcastContent { return &Broadcast2{} }

// Number implements round.Round.
func (Kround2) Number() round.Number { return 2 }

func (r Kround2) MarshalJSON() ([]byte, error) {
	nmods := make(map[party.ID][]byte)
	ss := make(map[party.ID][]byte)
	ts := make(map[party.ID][]byte)
	for id, ped := range r.Pedersen {
		nmods[id] = ped.N().Bytes()
		ss[id] = ped.S().Bytes()
		ts[id] = ped.T().Bytes()
	}
	cs := make(map[party.ID]string)
	for id, c := range r.Commitments {
		str := base64.StdEncoding.EncodeToString(c)
		cs[id] = str
	}

	mr2, e := json.Marshal(map[string]interface{}{
		"VSSPolynomials": r.VSSPolynomials,
		"Commitments":    cs,
		"RIDs":           r.RIDs,
		"ChainKeys":      r.ChainKeys,
		"ShareReceived":  r.ShareReceived,
		"ElGamalPublic":  r.ElGamalPublic,
		"PaillierPublic": r.PaillierPublic,
		"NModulus":       nmods,
		"S":              ss,
		"T":              ts,
		"ElGamalSecret":  r.ElGamalSecret,
		"PaillierSecret": r.PaillierSecret,
		"PedersenSecret": r.PedersenSecret.Bytes(),
		"SchnorrRand":    r.SchnorrRand,
		"Decommitment":   r.Decommitment,
	})
	if e != nil {
		fmt.Println(e)
		return nil, e
	}
	r1, e := json.Marshal(r.Kround1)
	if e != nil {
		fmt.Println(e)
		return nil, e
	}
	return jsontools.JoinJSON(mr2, r1)
}

func (r *Kround2) UnmarshalJSON(j []byte) error {
	var tmp map[string]json.RawMessage
	if err := json.Unmarshal(j, &tmp); err != nil {
		fmt.Println("kr2 unmarshal failed @ tmp:", err)
		return err
	}

	var r1 *Kround1
	if err := json.Unmarshal(j, &r1); err != nil {
		fmt.Println("kr2 unmarshal failed @ kr1:", err)
		return err
	}
	r.Kround1 = r1

	vsspoly := make(map[party.ID]*polynomial.Exponent)
	polys := make(map[party.ID]json.RawMessage)
	if err := json.Unmarshal(tmp["VSSPolynomials"], &polys); err != nil {
		fmt.Println("kr2 unmarshal failed @ polys:", err)
		return err
	}
	for i, p := range polys {
		vsspoly[i] = polynomial.EmptyExponent(curve.Secp256k1{})
		if err := json.Unmarshal(p, vsspoly[i]); err != nil {
			fmt.Println("kr2 unmarshal failed @ vsspoly[i]:", err)
			return err
		}
	}
	r.VSSPolynomials = vsspoly

	cmtmts := make(map[party.ID]hash.Commitment)
	cs := make(map[party.ID]string)
	if err := json.Unmarshal(tmp["Commitments"], &cs); err != nil {
		fmt.Println("kr2 unmarshal failed @ cs:", err)
		return err
	}
	for id, c := range cs {
		str, e := base64.StdEncoding.DecodeString(c)
		if e != nil {
			return e
		}
		cmtmts[id] = str
	}
	r.Commitments = cmtmts

	rids := make(map[party.ID]types.RID)
	if err := json.Unmarshal(tmp["RIDs"], &rids); err != nil {
		fmt.Println("kr2 unmarshal failed @ rids:", err)
		return err
	}
	r.RIDs = rids

	ckeys := make(map[party.ID]types.RID)
	if err := json.Unmarshal(tmp["ChainKeys"], &ckeys); err != nil {
		fmt.Println("kr2 unmarshal failed @ ckeys:", err)
		return err
	}
	r.ChainKeys = ckeys

	shreceived := make(map[party.ID]json.RawMessage)
	shares := make(map[party.ID]curve.Scalar)
	if err := json.Unmarshal(tmp["ShareReceived"], &shreceived); err != nil {
		fmt.Println("kr2 unmarshal failed @ shreceived:", err)
		return err
	}
	for k, sh := range shreceived {
		shares[k] = &curve.Secp256k1Scalar{}
		e := shares[k].UnmarshalJSON(sh)
		if e != nil {
			fmt.Println("kr2 unmarshal failed @ shreceived range:", e)
			return e
		}
	}
	r.ShareReceived = shares

	elgmlstrings := make(map[party.ID]json.RawMessage)
	elgmlpub := make(map[party.ID]curve.Point)
	if err := json.Unmarshal(tmp["ElGamalPublic"], &elgmlstrings); err != nil {
		fmt.Println("kr2 unmarshal failed @ elgmlstrings:", err)
		return err
	}
	for k, elg := range elgmlstrings {
		elgmlpub[k] = &curve.Secp256k1Point{}
		e := elgmlpub[k].UnmarshalJSON(elg)
		if e != nil {
			fmt.Println("kr2 unmarshal failed @ elgmlstrings range:", e)
		}
	}
	r.ElGamalPublic = elgmlpub

	paillierpub := make(map[party.ID]*paillier.PublicKey)
	paillierparties := make(map[party.ID]json.RawMessage)
	if err := json.Unmarshal(tmp["PaillierPublic"], &paillierparties); err != nil {
		fmt.Println("kr2 unmarshal failed @ paillierparties:", err)
		return err
	}
	for party, jsn := range paillierparties {
		var pub *paillier.PublicKey
		if err := json.Unmarshal(jsn, &pub); err != nil {
			fmt.Println("kr2 unmarshal failed @ pub:", err)
			return err
		}
		paillierpub[party] = pub
	}
	r.PaillierPublic = paillierpub

	nmod := make(map[party.ID]*arith.Modulus)
	nmodBytes := make(map[party.ID][]byte)
	if err := json.Unmarshal(tmp["NModulus"], &nmodBytes); err != nil {
		fmt.Println("kr2 unmarshal failed @ nmod:", err)
		return err
	}
	for k, nm := range nmodBytes {
		nm := nm
		modulus := arith.ModulusFromBytes(nm)
		nmod[k] = &modulus
	}
	s := make(map[party.ID]*saferith.Nat)
	t := make(map[party.ID]*saferith.Nat)
	sBytes := make(map[party.ID][]byte)
	tBytes := make(map[party.ID][]byte)
	if err := json.Unmarshal(tmp["S"], &sBytes); err != nil {
		fmt.Println("kr2 unmarshal failed @ s:", err)
		return err
	}
	if err := json.Unmarshal(tmp["T"], &tBytes); err != nil {
		fmt.Println("kr2 unmarshal failed @ t:", err)
		return err
	}
	for k, sb := range sBytes {
		sb := sb
		nat := &saferith.Nat{}
		s[k] = nat.SetBytes(sb)
	}
	for k, tb := range tBytes {
		tb := tb
		nat := &saferith.Nat{}
		t[k] = nat.SetBytes(tb)
	}
	peds := make(map[party.ID]*pedersen.Parameters)
	for k := range nmod {
		peds[k] = pedersen.New(nmod[k], s[k], t[k])
	}
	r.Pedersen = peds

	var elgmlsecret curve.Secp256k1Scalar
	if err := json.Unmarshal(tmp["ElGamalSecret"], &elgmlsecret); err != nil {
		fmt.Println("kr2 unmarshal failed @ elgmlsecret:", err)
		return err
	}
	r.ElGamalSecret = &elgmlsecret

	var pailliersecret *paillier.SecretKey
	if err := json.Unmarshal(tmp["PaillierSecret"], &pailliersecret); err != nil {
		fmt.Println("kr2 unmarshal failed @ pailliersecret:", err)
		return err
	}
	r.PaillierSecret = pailliersecret

	var pedersensecret *saferith.Nat
	var pedersensecretBytes []byte
	if err := json.Unmarshal(tmp["PedersenSecret"], &pedersensecretBytes); err != nil {
		fmt.Println("kr2 unmarshal failed @ pedersensecret:", err)
		return err
	}
	pedersensecret = &saferith.Nat{}
	pedersensecret.SetBytes(pedersensecretBytes)
	r.PedersenSecret = pedersensecret

	var schnorrrand = &zksch.Randomness{}
	if err := schnorrrand.UnmarshalJSON(tmp["SchnorrRand"]); err != nil {
		fmt.Println("kr2 unmarshal failed @ schnorrand:", err)
		return err
	}
	r.SchnorrRand = schnorrrand

	var decommitment hash.Decommitment
	if err := json.Unmarshal(tmp["Decommitment"], &decommitment); err != nil {
		fmt.Println("kr2 unmarshal failed @ decommitment:", err)
		return err
	}
	r.Decommitment = decommitment

	return nil
}

func (b Broadcast2) MarshalJSON() ([]byte, error) {
	return json.Marshal(map[string]interface{}{
		"keyB2Commitment": b.Commitment,
	})
}

func (b *Broadcast2) UnmarshalJSON(j []byte) error {
	var tmp map[string]json.RawMessage
	if e := json.Unmarshal(j, &tmp); e != nil {
		fmt.Println("Failed to unmarshal Broadcast2 @ tmp:", e)
		return e
	}

	hc := hash.Commitment{}
	if e := json.Unmarshal(tmp["keyB2Commitment"], &hc); e != nil {
		fmt.Println("Failed to unmarshal Broadcast2 @ hc:", e)
		return e
	}
	b.Commitment = hc
	return nil
}
