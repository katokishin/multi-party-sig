package ecdsa

import (
	"errors"

	"github.com/taurusgroup/multi-party-sig/internal/types"
	"github.com/taurusgroup/multi-party-sig/pkg/math/curve"
	"github.com/taurusgroup/multi-party-sig/pkg/party"
)

type PreSignature struct {
	// ID is a random identifier for this specific presignature.
	ID    types.RID
	Group curve.Curve
	// R = δ⁻¹⋅Γ = δ⁻¹⋅(∑ⱼ Γⱼ) = (∑ⱼδ⁻¹γⱼ)⋅G = k⁻¹⋅G
	R curve.Point
	// RBar[j] = δ⁻¹⋅Δⱼ = (δ⁻¹kⱼ)⋅Γ = (k⁻¹kⱼ)⋅G
	RBar map[party.ID]curve.Point
	// S[j] = χⱼ⋅R
	S map[party.ID]curve.Point
	// KShare = kᵢ
	KShare curve.Scalar
	// ChiShare = χᵢ
	ChiShare curve.Scalar
}

// SignatureShare represents an individual additive share of the signature's "s" component.
type SignatureShare = curve.Scalar

// SignatureShare returns this party's share σᵢ = kᵢm+rχᵢ, where s = ∑ⱼσⱼ.
func (sig *PreSignature) SignatureShare(hash []byte) curve.Scalar {
	m := curve.FromHash(sig.Group, hash)
	r := sig.R.XScalar()
	mk := m.Mul(sig.KShare)
	rx := r.Mul(sig.ChiShare)
	sigma := mk.Add(rx)
	return sigma
}

// Signature combines the given shares σⱼ and returns a pair (R,S), where S=∑ⱼσⱼ.
func (sig *PreSignature) Signature(shares map[party.ID]SignatureShare) *Signature {
	s := sig.Group.NewScalar()
	for _, sigma := range shares {
		s.Add(sigma)
	}
	return &Signature{
		R: sig.R,
		S: s,
	}
}

// VerifySignatureShares should be called if the signature returned by PreSignature.Signature is not valid.
// It returns the list of parties whose shares are invalid.
func (sig *PreSignature) VerifySignatureShares(shares map[party.ID]SignatureShare, hash []byte) (culprits []party.ID) {
	r := sig.R.XScalar()
	m := curve.FromHash(sig.Group, hash)
	for j, share := range shares {
		Rj, Sj := sig.RBar[j], sig.S[j]
		if Rj == nil || Sj == nil {
			culprits = append(culprits, j)
			continue
		}
		lhs := share.Act(sig.R)
		rhs := m.Act(Rj).Add(r.Act(Sj))
		if !lhs.Equal(rhs) {
			culprits = append(culprits, j)
		}
	}
	return
}

func (sig *PreSignature) Validate() error {
	if len(sig.RBar) != len(sig.S) {
		return errors.New("presignature: different number of R,S shares")
	}

	for id, R := range sig.RBar {
		if S, ok := sig.S[id]; !ok || S.IsIdentity() {
			return errors.New("presignature: S invalid")
		}
		if R.IsIdentity() {
			return errors.New("presignature: RBar invalid")
		}
	}
	if sig.R.IsIdentity() {
		return errors.New("presignature: R is identity")
	}
	if err := sig.ID.Validate(); err != nil {
		// TODO
		//return fmt.Errorf("presignature: %w", err)
	}
	if sig.ChiShare.IsZero() || sig.KShare.IsZero() {
		return errors.New("ChiShare or KShare is invalid")
	}
	return nil
}

func (sig *PreSignature) SignerIDs() party.IDSlice {
	ids := make([]party.ID, 0, len(sig.RBar))
	for id := range sig.RBar {
		ids = append(ids, id)
	}
	return party.NewIDSlice(ids)
}
