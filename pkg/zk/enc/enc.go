package zkenc

import (
	"crypto/rand"
	"encoding/json"

	"github.com/cronokirby/saferith"
	"github.com/taurusgroup/multi-party-sig/pkg/hash"
	"github.com/taurusgroup/multi-party-sig/pkg/math/arith"
	"github.com/taurusgroup/multi-party-sig/pkg/math/curve"
	"github.com/taurusgroup/multi-party-sig/pkg/math/sample"
	"github.com/taurusgroup/multi-party-sig/pkg/paillier"
	"github.com/taurusgroup/multi-party-sig/pkg/pedersen"
)

type Public struct {
	// K = Enc₀(k;ρ)
	K *paillier.Ciphertext

	Prover *paillier.PublicKey
	Aux    *pedersen.Parameters
}
type Private struct {
	// K = k ∈ 2ˡ = Dec₀(K)
	// plaintext of K
	K *saferith.Int

	// Rho = ρ
	// nonce of K
	Rho *saferith.Nat
}

type Commitment struct {
	// S = sᵏtᵘ
	S *saferith.Nat
	// A = Enc₀ (α, r)
	A *paillier.Ciphertext
	// C = sᵃtᵍ
	C *saferith.Nat
}

type Proof struct {
	*Commitment
	// Z₁ = α + e⋅k
	Z1 *saferith.Int
	// Z₂ = r ⋅ ρᵉ mod N₀
	Z2 *saferith.Nat
	// Z₃ = γ + e⋅μ
	Z3 *saferith.Int
}

func (p *Proof) IsValid(public Public) bool {
	if p == nil {
		return false
	}
	if !public.Prover.ValidateCiphertexts(p.A) {
		return false
	}
	if !arith.IsValidNatModN(public.Prover.N(), p.Z2) {
		return false
	}
	return true
}

func NewProof(group curve.Curve, hash *hash.Hash, public Public, private Private) *Proof {
	N := public.Prover.N()
	NModulus := public.Prover.Modulus()

	alpha := sample.IntervalLEps(rand.Reader)
	r := sample.UnitModN(rand.Reader, N)
	mu := sample.IntervalLN(rand.Reader)
	gamma := sample.IntervalLEpsN(rand.Reader)

	A := public.Prover.EncWithNonce(alpha, r)

	commitment := &Commitment{
		S: public.Aux.Commit(private.K, mu),
		A: A,
		C: public.Aux.Commit(alpha, gamma),
	}

	e, _ := challenge(hash, group, public, commitment)

	z1 := new(saferith.Int).SetInt(private.K)
	z1.Mul(e, z1, -1)
	z1.Add(z1, alpha, -1)

	z2 := NModulus.ExpI(private.Rho, e)
	z2.ModMul(z2, r, N)

	z3 := new(saferith.Int).Mul(e, mu, -1)
	z3.Add(z3, gamma, -1)

	return &Proof{
		Commitment: commitment,
		Z1:         z1,
		Z2:         z2,
		Z3:         z3,
	}
}

func (p Proof) Verify(group curve.Curve, hash *hash.Hash, public Public) bool {
	if !p.IsValid(public) {
		return false
	}

	prover := public.Prover

	if !arith.IsInIntervalLEps(p.Z1) {
		return false
	}

	e, err := challenge(hash, group, public, p.Commitment)
	if err != nil {
		return false
	}

	if !public.Aux.Verify(p.Z1, p.Z3, e, p.C, p.S) {
		return false
	}

	{
		// lhs = Enc(z₁;z₂)
		lhs := prover.EncWithNonce(p.Z1, p.Z2)

		// rhs = (e ⊙ K) ⊕ A
		rhs := public.K.Clone().Mul(prover, e).Add(prover, p.A)
		if !lhs.Equal(rhs) {
			return false
		}
	}

	return true
}

func (p Proof) MarshalJSON() ([]byte, error) {
	z1b, e := p.Z1.MarshalBinary()
	if e != nil {
		return nil, e
	}
	z2b, e := p.Z2.MarshalBinary()
	if e != nil {
		return nil, e
	}
	z3b, e := p.Z3.MarshalBinary()
	if e != nil {
		return nil, e
	}
	return json.Marshal(map[string]interface{}{
		"Commitment": p.Commitment,
		"Z1":         z1b,
		"Z2":         z2b,
		"Z3":         z3b,
	})
}

func (p *Proof) UnmarshalJSON(j []byte) error {
	var tmp map[string]json.RawMessage
	if e := json.Unmarshal(j, &tmp); e != nil {
		return e
	}

	var z1 = *&saferith.Int{}
	var z2 = *&saferith.Modulus{}
	var z3 = *&saferith.Int{}
	z1bytes := []byte{}
	z2bytes := []byte{}
	z3bytes := []byte{}

	if e := json.Unmarshal(tmp["Z1"], &z1bytes); e != nil {
		return e
	}
	if e := json.Unmarshal(tmp["Z2"], &z2bytes); e != nil {
		return e
	}
	if e := json.Unmarshal(tmp["Z3"], &z3bytes); e != nil {
		return e
	}
	if e := z1.UnmarshalBinary(z1bytes); e != nil {
		return e
	}
	if e := z2.UnmarshalBinary(z2bytes); e != nil {
		return e
	}
	if e := z3.UnmarshalBinary(z3bytes); e != nil {
		return e
	}

	var commitment *Commitment
	if e := json.Unmarshal(tmp["Commitment"], &commitment); e != nil {
		return e
	}

	p.Z1 = &z1
	p.Z2 = z2.Nat()
	p.Z3 = &z3
	p.Commitment = commitment
	return nil
}

func (c Commitment) MarshalJSON() ([]byte, error) {
	sb, e := c.S.MarshalBinary()
	if e != nil {
		return nil, e
	}
	cb, e := c.C.MarshalBinary()
	if e != nil {
		return nil, e
	}
	return json.Marshal(map[string]interface{}{
		"S": sb,
		"C": cb,
		"A": c.A,
	})
}

func (c *Commitment) UnmarshalJSON(j []byte) error {
	var tmp map[string]json.RawMessage
	if e := json.Unmarshal(j, &tmp); e != nil {
		return e
	}

	s := *&saferith.Modulus{}
	var sBytes []byte
	cv := *&saferith.Modulus{}
	var cBytes []byte

	if e := json.Unmarshal(tmp["S"], &sBytes); e != nil {
		return e
	}
	if e := s.UnmarshalBinary(sBytes); e != nil {
		return e
	}

	if e := json.Unmarshal(tmp["C"], &cBytes); e != nil {
		return e
	}
	if e := cv.UnmarshalBinary(cBytes); e != nil {
		return e
	}

	var a *paillier.Ciphertext
	if e := json.Unmarshal(tmp["A"], &a); e != nil {
		return e
	}

	c.A = a
	c.C = cv.Nat()
	c.S = s.Nat()
	return nil
}

func challenge(hash *hash.Hash, group curve.Curve, public Public, commitment *Commitment) (e *saferith.Int, err error) {
	err = hash.WriteAny(public.Aux, public.Prover, public.K,
		commitment.S, commitment.A, commitment.C)
	e = sample.IntervalScalar(hash.Digest(), group)
	return
}
