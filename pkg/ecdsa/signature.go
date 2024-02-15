package ecdsa

import (
	"github.com/taurusgroup/multi-party-sig/pkg/math/curve"
)

type Signature struct {
	R curve.Point
	S curve.Scalar
}

// EmptySignature returns a new signature with a given curve, ready to be unmarshalled.
func EmptySignature(group curve.Curve) Signature {
	return Signature{R: group.NewPoint(), S: group.NewScalar()}
}

// Verify is a custom signature format using curve data.
func (sig Signature) Verify(X curve.Point, hash []byte) bool {
	group := X.Curve()

	r := sig.R.XScalar()
	if r.IsZero() || sig.S.IsZero() {
		return false
	}

	m := curve.FromHash(group, hash)
	sInv := group.NewScalar().Set(sig.S).Invert()
	mG := m.ActOnBase()
	rX := r.Act(X)
	R2 := mG.Add(rX)
	R2 = sInv.Act(R2)
	return R2.Equal(sig.R)
}

// Return a 65 byte signature easily decoded for use in Ethereum (0x02 or 0x03, R.x, S)
func (sig Signature) SigEthereum() ([]byte, error) {
	IsOverHalfOrder := sig.S.IsOverHalfOrder() // s-values greater than secp256k1n/2 are considered invalid

	if IsOverHalfOrder {
		sig.S.Negate()
	}

	// Results in 33 bytes
	// 0x02 for even y, 0x03 for odd y, followed by 32 bytes of r.x
	r, err := sig.R.MarshalBinary()
	if err != nil {
		return nil, err
	}
	// 32 byte signature
	s, err := sig.S.MarshalBinary()
	if err != nil {
		return nil, err
	}

	rs := make([]byte, 0, 65)
	rs = append(rs, r...)
	rs = append(rs, s...)

	return rs, nil
}
