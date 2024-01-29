package keygen

import (
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/cronokirby/safenum"
	"github.com/taurusgroup/multi-party-sig/internal/jsontools"
	"github.com/taurusgroup/multi-party-sig/internal/round"
	"github.com/taurusgroup/multi-party-sig/internal/types"
	"github.com/taurusgroup/multi-party-sig/pkg/hash"
	"github.com/taurusgroup/multi-party-sig/pkg/math/curve"
	"github.com/taurusgroup/multi-party-sig/pkg/math/polynomial"
	"github.com/taurusgroup/multi-party-sig/pkg/math/sample"
	"github.com/taurusgroup/multi-party-sig/pkg/paillier"
	"github.com/taurusgroup/multi-party-sig/pkg/party"
	zksch "github.com/taurusgroup/multi-party-sig/pkg/zk/sch"
)

var _ round.Round = (*Kround1)(nil)

type Kround1 struct {
	*round.Helper

	// PreviousSecretECDSA = sk'ᵢ
	// Contains the previous secret ECDSA key share which is being refreshed
	// Keygen:  sk'ᵢ = nil
	// Refresh: sk'ᵢ = sk'ᵢ
	PreviousSecretECDSA curve.Scalar

	// PreviousPublicSharesECDSA[j] = pk'ⱼ
	// Keygen:  pk'ⱼ = nil
	// Refresh: pk'ⱼ = pk'ⱼ
	PreviousPublicSharesECDSA map[party.ID]curve.Point

	// PreviousChainKey contains the chain key, if we're refreshing
	//
	// In that case, we will simply use the previous chain key at the very end.
	PreviousChainKey types.RID

	// VSSSecret = fᵢ(X)
	// Polynomial from which the new secret shares are computed.
	// Keygen:  fᵢ(0) = xⁱ
	// Refresh: fᵢ(0) = 0
	VSSSecret *polynomial.Polynomial
}

// VerifyMessage implements round.Round.
func (r *Kround1) VerifyMessage(round.Message) error { return nil }

// StoreMessage implements round.Round.
func (r *Kround1) StoreMessage(round.Message) error { return nil }

// Finalize implements round.Round
//
// - sample Paillier (pᵢ, qᵢ)
// - sample Pedersen Nᵢ, sᵢ, tᵢ
// - sample aᵢ  <- 𝔽
// - set Aᵢ = aᵢ⋅G
// - compute Fᵢ(X) = fᵢ(X)⋅G
// - sample ridᵢ <- {0,1}ᵏ
// - sample cᵢ <- {0,1}ᵏ
// - commit to message.
func (r *Kround1) Finalize(out []*round.Message) (round.Session, []*round.Message, error) {
	// generate Paillier and Pedersen
	PaillierSecret := paillier.NewSecretKey(nil)
	SelfPaillierPublic := PaillierSecret.PublicKey
	SelfPedersenPublic, PedersenSecret := PaillierSecret.GeneratePedersen()

	ElGamalSecret, ElGamalPublic := sample.ScalarPointPair(rand.Reader, r.Group())

	// save our own share already so we are consistent with what we receive from others
	SelfShare := r.VSSSecret.Evaluate(r.SelfID().Scalar(r.Group()))

	// set Fᵢ(X) = fᵢ(X)•G
	SelfVSSPolynomial := polynomial.NewPolynomialExponent(r.VSSSecret)

	// generate Schnorr randomness
	SchnorrRand := zksch.NewRandomness(rand.Reader, r.Group(), nil)

	// Sample RIDᵢ
	SelfRID, err := types.NewRID(rand.Reader)
	if err != nil {
		return r, nil, errors.New("failed to sample Rho")
	}
	chainKey, err := types.NewRID(rand.Reader)
	if err != nil {
		return r, nil, errors.New("failed to sample c")
	}

	// commit to data in message 2
	SelfCommitment, Decommitment, err := r.HashForID(r.SelfID()).Commit(
		SelfRID, chainKey, SelfVSSPolynomial, SchnorrRand.Commitment(), ElGamalPublic,
		SelfPedersenPublic.N(), SelfPedersenPublic.S(), SelfPedersenPublic.T())
	if err != nil {
		return r, nil, errors.New("failed to commit")
	}

	// should be broadcast but we don't need that here
	msg := &Broadcast2{Commitment: SelfCommitment}
	out = r.BroadcastMessage(out, msg)

	nextRound := &Kround2{
		Kround1:        r,
		VSSPolynomials: map[party.ID]*polynomial.Exponent{r.SelfID(): SelfVSSPolynomial},
		Commitments:    map[party.ID]hash.Commitment{r.SelfID(): SelfCommitment},
		RIDs:           map[party.ID]types.RID{r.SelfID(): SelfRID},
		ChainKeys:      map[party.ID]types.RID{r.SelfID(): chainKey},
		ShareReceived:  map[party.ID]curve.Scalar{r.SelfID(): SelfShare},
		ElGamalPublic:  map[party.ID]curve.Point{r.SelfID(): ElGamalPublic},
		PaillierPublic: map[party.ID]*paillier.PublicKey{r.SelfID(): SelfPaillierPublic},
		NModulus:       map[party.ID]*safenum.Modulus{r.SelfID(): SelfPedersenPublic.N()},
		S:              map[party.ID]*safenum.Nat{r.SelfID(): SelfPedersenPublic.S()},
		T:              map[party.ID]*safenum.Nat{r.SelfID(): SelfPedersenPublic.T()},
		ElGamalSecret:  ElGamalSecret,
		PaillierSecret: PaillierSecret,
		PedersenSecret: PedersenSecret,
		SchnorrRand:    SchnorrRand,
		Decommitment:   Decommitment,
	}
	return nextRound, out, nil
}

// PreviousRound implements round.Round.
func (Kround1) PreviousRound() round.Round { return nil }

// MessageContent implements round.Round.
func (Kround1) MessageContent() round.Content { return nil }

// Number implements round.Round.
func (Kround1) Number() round.Number { return 1 }

func (r *Kround1) MarshalJSON() ([]byte, error) {
	h, e := r.Helper.MarshalJSON()
	if e != nil {
		fmt.Println(e)
		return nil, e
	}
	r1, e := json.Marshal(map[string]interface{}{
		"VSSSecret": r.VSSSecret,
	})
	if e != nil {
		fmt.Println(e)
		return nil, e
	}
	return jsontools.JoinJSON(r1, h)
}

func (r *Kround1) UnmarshalJSON(j []byte) error {
	var tmp map[string]json.RawMessage
	if err := json.Unmarshal(j, &tmp); err != nil {
		fmt.Println("kr1 unmarshal failed @ tmp:", err)
		return err
	}

	var vsss *polynomial.Polynomial
	if err := json.Unmarshal(tmp["VSSSecret"], &vsss); err != nil {
		fmt.Println("kr1 unmarshal failed @ vsss:", err)
		return err
	}

	var h *round.Helper
	if err := json.Unmarshal(j, &h); err != nil {
		fmt.Println("kr1 unmarshal failed @ h:", err)
		return err
	}
	r.Helper = h

	r.Info = h.Info
	r.Pool = h.Pool
	r.OtherPartyIDsSlice = h.OtherPartyIDsSlice
	r.PartyIDsSlice = h.PartyIDsSlice
	r.Ssid = h.Ssid

	r.VSSSecret = vsss
	return nil
}
