package zkfac

import (
	"crypto/rand"
	"encoding/json"

	"github.com/cronokirby/saferith"
	"github.com/taurusgroup/multi-party-sig/pkg/hash"
	"github.com/taurusgroup/multi-party-sig/pkg/math/arith"
	"github.com/taurusgroup/multi-party-sig/pkg/math/sample"
	"github.com/taurusgroup/multi-party-sig/pkg/pedersen"
)

type Public struct {
	N   *saferith.Modulus
	Aux *pedersen.Parameters
}

type Private struct {
	P, Q *saferith.Nat
}

type Commitment struct {
	P *saferith.Nat
	Q *saferith.Nat
	A *saferith.Nat
	B *saferith.Nat
	T *saferith.Nat
}

type Proof struct {
	Comm  Commitment
	Sigma *saferith.Int
	Z1    *saferith.Int
	Z2    *saferith.Int
	W1    *saferith.Int
	W2    *saferith.Int
	V     *saferith.Int
}

func NewProof(private Private, hash *hash.Hash, public Public) *Proof {
	Nhat := public.Aux.NArith()

	// Figure 28, point 1.
	alpha := sample.IntervalLEpsRootN(rand.Reader)
	beta := sample.IntervalLEpsRootN(rand.Reader)
	mu := sample.IntervalLN(rand.Reader)
	nu := sample.IntervalLN(rand.Reader)
	sigma := sample.IntervalLN2(rand.Reader)
	r := sample.IntervalLEpsN2(rand.Reader)
	x := sample.IntervalLEpsN(rand.Reader)
	y := sample.IntervalLEpsN(rand.Reader)

	pInt := new(saferith.Int).SetNat(private.P)
	qInt := new(saferith.Int).SetNat(private.Q)
	P := public.Aux.Commit(pInt, mu)
	Q := public.Aux.Commit(qInt, nu)
	A := public.Aux.Commit(alpha, x)
	B := public.Aux.Commit(beta, y)
	T := Nhat.ExpI(Q, alpha)
	T.ModMul(T, Nhat.ExpI(public.Aux.T(), r), Nhat.Modulus)

	comm := Commitment{P, Q, A, B, T}

	// Figure 28, point 2:
	e, _ := challenge(hash, public, comm)

	// Figure 28, point 3:
	// "..., and sends (z, u, v) to the verifier, where"
	// DEVIATION:
	// This seems like another typo, because there's no "u",
	// so I assume they meant "sends (z1, z2, w1, w2, v)".
	z1 := new(saferith.Int).Mul(e, pInt, -1)
	z1.Add(z1, alpha, -1)
	z2 := new(saferith.Int).Mul(e, qInt, -1)
	z2.Add(z2, beta, -1)
	w1 := new(saferith.Int).Mul(e, mu, -1)
	w1.Add(w1, x, -1)
	w2 := new(saferith.Int).Mul(e, nu, -1)
	w2.Add(w2, y, -1)
	sigmaHat := new(saferith.Int).Mul(nu, pInt, -1)
	sigmaHat = sigmaHat.Neg(1)
	sigmaHat.Add(sigmaHat, sigma, -1)
	v := new(saferith.Int).Mul(e, sigmaHat, -1)
	v.Add(v, r, -1)

	return &Proof{
		Comm:  comm,
		Sigma: sigma,
		Z1:    z1,
		Z2:    z2,
		W1:    w1,
		W2:    w2,
		V:     v,
	}
}

func (p *Proof) Verify(public Public, hash *hash.Hash) bool {
	if p == nil {
		return false
	}

	e, err := challenge(hash, public, p.Comm)
	if err != nil {
		return false
	}

	N0 := public.N
	NhatArith := public.Aux.NArith()
	Nhat := NhatArith.Modulus

	if !public.Aux.Verify(p.Z1, p.W1, e, p.Comm.A, p.Comm.P) {
		return false
	}

	if !public.Aux.Verify(p.Z2, p.W2, e, p.Comm.B, p.Comm.Q) {
		return false
	}

	// Setting R this way avoid issues with the other exponent functions which
	// might try and apply the CRT.
	R := new(saferith.Nat).SetNat(public.Aux.S())
	R = NhatArith.Exp(R, N0.Nat())
	R.ModMul(R, NhatArith.ExpI(public.Aux.T(), p.Sigma), Nhat)

	lhs := NhatArith.ExpI(p.Comm.Q, p.Z1)
	lhs.ModMul(lhs, NhatArith.ExpI(public.Aux.T(), p.V), Nhat)
	rhs := NhatArith.ExpI(R, e)
	rhs.ModMul(rhs, p.Comm.T, Nhat)
	if lhs.Eq(rhs) != 1 {
		return false
	}

	// DEVIATION: for the bounds to work, we add an extra bit, to ensure that we don't have spurious failures.
	return arith.IsInIntervalLEpsPlus1RootN(p.Z1) && arith.IsInIntervalLEpsPlus1RootN(p.Z2)
}

func (p Proof) MarshalJSON() ([]byte, error) {
	sb, e := p.Sigma.MarshalBinary()
	if e != nil {
		return nil, e
	}
	z1b, e := p.Z1.MarshalBinary()
	if e != nil {
		return nil, e
	}
	z2b, e := p.Z2.MarshalBinary()
	if e != nil {
		return nil, e
	}
	w1b, e := p.W1.MarshalBinary()
	if e != nil {
		return nil, e
	}
	w2b, e := p.W2.MarshalBinary()
	if e != nil {
		return nil, e
	}
	vb, e := p.V.MarshalBinary()
	if e != nil {
		return nil, e
	}
	return json.Marshal(map[string]interface{}{
		"Comm":  p.Comm,
		"Sigma": sb,
		"Z1":    z1b,
		"Z2":    z2b,
		"W1":    w1b,
		"W2":    w2b,
		"V":     vb,
	})
}

func (p *Proof) UnmarshalJSON(j []byte) error {
	var tmp map[string]json.RawMessage
	if e := json.Unmarshal(j, &tmp); e != nil {
		return e
	}

	var sigma = *&saferith.Int{}
	var z1 = *&saferith.Int{}
	var z2 = *&saferith.Int{}
	var w1 = *&saferith.Int{}
	var w2 = *&saferith.Int{}
	var v = *&saferith.Int{}
	sigmaBytes := []byte{}
	z1Bytes := []byte{}
	z2Bytes := []byte{}
	w1Bytes := []byte{}
	w2Bytes := []byte{}
	vBytes := []byte{}

	if e := json.Unmarshal(tmp["Sigma"], &sigmaBytes); e != nil {
		return e
	}
	if e := json.Unmarshal(tmp["Z1"], &z1Bytes); e != nil {
		return e
	}
	if e := json.Unmarshal(tmp["Z2"], &z2Bytes); e != nil {
		return e
	}
	if e := json.Unmarshal(tmp["W1"], &w1Bytes); e != nil {
		return e
	}
	if e := json.Unmarshal(tmp["W2"], &w2Bytes); e != nil {
		return e
	}
	if e := json.Unmarshal(tmp["V"], &vBytes); e != nil {
		return e
	}

	if e := sigma.UnmarshalBinary(sigmaBytes); e != nil {
		return e
	}
	if e := z1.UnmarshalBinary(z1Bytes); e != nil {
		return e
	}
	if e := z2.UnmarshalBinary(z2Bytes); e != nil {
		return e
	}
	if e := w1.UnmarshalBinary(w1Bytes); e != nil {
		return e
	}
	if e := w2.UnmarshalBinary(w2Bytes); e != nil {
		return e
	}
	if e := v.UnmarshalBinary(vBytes); e != nil {
		return e
	}

	var comm Commitment
	if e := json.Unmarshal(tmp["Comm"], &comm); e != nil {
		return e
	}

	p.Comm = comm
	p.Sigma = &sigma
	p.Z1 = &z1
	p.Z2 = &z2
	p.W1 = &w1
	p.W2 = &w2
	p.V = &v
	return nil
}

func (c Commitment) MarshalJSON() ([]byte, error) {
	pb, e := c.P.MarshalBinary()
	if e != nil {
		return nil, e
	}
	qb, e := c.Q.MarshalBinary()
	if e != nil {
		return nil, e
	}
	ab, e := c.A.MarshalBinary()
	if e != nil {
		return nil, e
	}
	bb, e := c.B.MarshalBinary()
	if e != nil {
		return nil, e
	}
	tb, e := c.T.MarshalBinary()
	if e != nil {
		return nil, e
	}
	return json.Marshal(map[string]interface{}{
		"P": pb,
		"Q": qb,
		"A": ab,
		"B": bb,
		"T": tb,
	})
}

func (c *Commitment) UnmarshalJSON(j []byte) error {
	var tmp map[string]json.RawMessage
	if e := json.Unmarshal(j, &tmp); e != nil {
		return e
	}

	var p = *&saferith.Modulus{}
	var q = *&saferith.Modulus{}
	var a = *&saferith.Modulus{}
	var b = *&saferith.Modulus{}
	var t = *&saferith.Modulus{}
	pBytes := []byte{}
	qBytes := []byte{}
	aBytes := []byte{}
	bBytes := []byte{}
	tBytes := []byte{}

	if e := json.Unmarshal(tmp["P"], &pBytes); e != nil {
		return e
	}
	if e := json.Unmarshal(tmp["Q"], &qBytes); e != nil {
		return e
	}
	if e := json.Unmarshal(tmp["A"], &aBytes); e != nil {
		return e
	}
	if e := json.Unmarshal(tmp["B"], &bBytes); e != nil {
		return e
	}
	if e := json.Unmarshal(tmp["T"], &tBytes); e != nil {
		return e
	}

	if e := p.UnmarshalBinary(pBytes); e != nil {
		return e
	}
	if e := q.UnmarshalBinary(qBytes); e != nil {
		return e
	}
	if e := a.UnmarshalBinary(aBytes); e != nil {
		return e
	}
	if e := b.UnmarshalBinary(bBytes); e != nil {
		return e
	}
	if e := t.UnmarshalBinary(tBytes); e != nil {
		return e
	}

	c.P = p.Nat()
	c.Q = q.Nat()
	c.A = a.Nat()
	c.B = b.Nat()
	c.T = t.Nat()
	return nil
}

func challenge(hash *hash.Hash, public Public, commitment Commitment) (*saferith.Int, error) {
	err := hash.WriteAny(public.Aux, commitment.P, commitment.Q, commitment.A, commitment.B, commitment.T)
	if err != nil {
		return nil, err
	}
	// Figure 28, point 2:
	// "Verifier replies with e <- +-q"
	// DEVIATION:
	// This doesn't make any sense, since we don't know the secret factor q,
	// and involving the size of scalars doesn't make sense.
	// I think that this is a typo in the paper, and instead it should
	// be +-2^eps.
	return sample.IntervalL(hash.Digest()), nil
	// return sample.IntervalEps(hash.Digest()), nil
}
