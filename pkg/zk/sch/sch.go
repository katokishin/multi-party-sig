package zksch

import (
	"crypto/rand"
	"io"

	"github.com/taurusgroup/multi-party-sig/internal/hash"
	"github.com/taurusgroup/multi-party-sig/pkg/math/curve"
	"github.com/taurusgroup/multi-party-sig/pkg/math/sample"
)

// Randomness = a ← ℤₚ.
type Randomness struct {
	a          curve.Scalar
	commitment Commitment
}

// Commitment = randomness•G, where
type Commitment struct {
	C curve.Point
}

// Response = randomness + H(..., commitment, public)•secret (mod p).
type Response struct {
	Z curve.Scalar
}

type Proof struct {
	C Commitment
	Z Response
}

// NewProof generates a Schnorr proof of knowledge of exponent for public, using the Fiat-Shamir transform.
func NewProof(group curve.Curve, hash *hash.Hash, public curve.Point, private curve.Scalar) *Proof {
	a := NewRandomness(rand.Reader, group)
	z := a.Prove(group, hash, public, private)
	return &Proof{
		C: *a.Commitment(),
		Z: *z,
	}
}

// NewRandomness creates a new a ∈ ℤₚ and the corresponding commitment C = a•G.
// This can be used to run the proof in a non-interactive way.
func NewRandomness(rand io.Reader, group curve.Curve) *Randomness {
	a, c := sample.ScalarPointPair(rand, group)
	return &Randomness{
		a:          a,
		commitment: Commitment{C: c},
	}
}

func challenge(group curve.Curve, hash *hash.Hash, commitment *Commitment, public curve.Point) (e curve.Scalar, err error) {
	err = hash.WriteAny(commitment.C, public)
	e = sample.Scalar(hash.Digest(), group)
	return
}

// Prove creates a Response = Randomness + H(..., Commitment, public)•secret (mod p).
func (r *Randomness) Prove(group curve.Curve, hash *hash.Hash, public curve.Point, secret curve.Scalar) *Response {
	if public.IsIdentity() || secret.IsZero() {
		return nil
	}
	e, err := challenge(group, hash, &r.commitment, public)
	if err != nil {
		return nil
	}
	es := e.Mul(secret)
	z := es.Add(r.a)
	return &Response{z}
}

// Commitment returns the commitment C = a•G for the randomness a.
func (r *Randomness) Commitment() *Commitment {
	return &r.commitment
}

// Verify checks that Response•G = Commitment + H(..., Commitment, public)•Public.
func (z *Response) Verify(group curve.Curve, hash *hash.Hash, public curve.Point, commitment *Commitment) bool {
	if z == nil || !z.IsValid() || public.IsIdentity() {
		return false
	}

	e, err := challenge(group, hash, commitment, public)
	if err != nil {
		return false
	}

	lhs := z.Z.ActOnBase()
	rhs := e.Act(public)
	rhs = rhs.Add(commitment.C)

	return lhs.Equal(rhs)
}

// Verify checks that Proof.Response•G = Proof.Commitment + H(..., Proof.Commitment, Public)•Public.
func (p *Proof) Verify(group curve.Curve, hash *hash.Hash, public curve.Point) bool {
	if !p.IsValid() {
		return false
	}
	return p.Z.Verify(group, hash, public, &p.C)
}

// WriteTo implements io.WriterTo.
func (c *Commitment) WriteTo(w io.Writer) (total int64, err error) {
	return c.C.WriteTo(w)
}

// Domain implements hash.WriterToWithDomain
func (Commitment) Domain() string {
	return "Schnorr Commitment"
}

func (c *Commitment) IsValid() bool {
	if c == nil || c.C.IsIdentity() {
		return false
	}
	return true
}

func (z *Response) IsValid() bool {
	if z == nil || z.Z.IsZero() {
		return false
	}
	return true
}

func (p *Proof) IsValid() bool {
	if p == nil || !p.Z.IsValid() || !p.C.IsValid() {
		return false
	}
	return true
}

func EmptyProof(group curve.Curve) *Proof {
	return &Proof{
		C: Commitment{C: group.NewPoint()},
		Z: Response{Z: group.NewScalar()},
	}
}

func EmptyResponse(group curve.Curve) *Response {
	return &Response{Z: group.NewScalar()}
}

func EmptyCommitment(group curve.Curve) *Commitment {
	return &Commitment{C: group.NewPoint()}
}
