package sign

import (
	"crypto/rand"
	"encoding/json"
	"fmt"

	"github.com/taurusgroup/multi-party-sig/internal/jsontools"
	"github.com/taurusgroup/multi-party-sig/internal/round"
	"github.com/taurusgroup/multi-party-sig/pkg/math/curve"
	"github.com/taurusgroup/multi-party-sig/pkg/math/sample"
	"github.com/taurusgroup/multi-party-sig/pkg/paillier"
	"github.com/taurusgroup/multi-party-sig/pkg/party"
	"github.com/taurusgroup/multi-party-sig/pkg/pedersen"
	zkenc "github.com/taurusgroup/multi-party-sig/pkg/zk/enc"
)

var _ round.Round = (*Sround1)(nil)

type Sround1 struct {
	*round.Helper

	PublicKey curve.Point

	SecretECDSA    curve.Scalar
	SecretPaillier *paillier.SecretKey
	Paillier       map[party.ID]*paillier.PublicKey
	Pedersen       map[party.ID]*pedersen.Parameters
	ECDSA          map[party.ID]curve.Point

	Message []byte
}

// VerifyMessage implements round.Round.
func (Sround1) VerifyMessage(round.Message) error { return nil }

// StoreMessage implements round.Round.
func (Sround1) StoreMessage(round.Message) error { return nil }

// Finalize implements round.Round
//
// - sample kᵢ, γᵢ <- 𝔽,
// - Γᵢ = [γᵢ]⋅G
// - Gᵢ = Encᵢ(γᵢ;νᵢ)
// - Kᵢ = Encᵢ(kᵢ;ρᵢ)
//
// NOTE
// The protocol instructs us to broadcast Kᵢ and Gᵢ, but the protocol we implement
// cannot handle identify aborts since we are in a point to point model.
// We do as described in [LN18].
//
// In the next round, we send a hash of all the {Kⱼ,Gⱼ}ⱼ.
// In two rounds, we compare the hashes received and if they are different then we abort.
func (r *Sround1) Finalize(out []*round.Message) (round.Session, []*round.Message, error) {
	// γᵢ <- 𝔽,
	// Γᵢ = [γᵢ]⋅G
	GammaShare, BigGammaShare := sample.ScalarPointPair(rand.Reader, r.Group())
	// Gᵢ = Encᵢ(γᵢ;νᵢ)
	G, GNonce := r.Paillier[r.SelfID()].Enc(curve.MakeInt(GammaShare))

	// kᵢ <- 𝔽,
	KShare := sample.Scalar(rand.Reader, r.Group())
	// Kᵢ = Encᵢ(kᵢ;ρᵢ)
	K, KNonce := r.Paillier[r.SelfID()].Enc(curve.MakeInt(KShare))

	otherIDs := r.OtherPartyIDs()
	broadcastMsg := broadcast2{K: K, G: G}
	out = r.BroadcastMessage(out, &broadcastMsg)
	errors := r.Pool.Parallelize(len(otherIDs), func(i int) interface{} {
		j := otherIDs[i]
		proof := zkenc.NewProof(r.Group(), r.HashForID(r.SelfID()), zkenc.Public{
			K:      K,
			Prover: r.Paillier[r.SelfID()],
			Aux:    r.Pedersen[j],
		}, zkenc.Private{
			K:   curve.MakeInt(KShare),
			Rho: KNonce,
		})

		out = r.SendMessage(out, &message2{
			ProofEnc: proof,
		}, j)
		return nil
	})
	for _, err := range errors {
		if err != nil {
			return r, nil, err.(error)
		}
	}

	return &Sround2{
		Sround1:       r,
		K:             map[party.ID]*paillier.Ciphertext{r.SelfID(): K},
		G:             map[party.ID]*paillier.Ciphertext{r.SelfID(): G},
		BigGammaShare: map[party.ID]curve.Point{r.SelfID(): BigGammaShare},
		GammaShare:    curve.MakeInt(GammaShare),
		KShare:        KShare,
		KNonce:        KNonce,
		GNonce:        GNonce,
	}, out, nil
}

// MessageContent implements round.Round.
func (Sround1) MessageContent() round.Content { return nil }

// Number implements round.Round.
func (Sround1) Number() round.Number { return 1 }

func (r *Sround1) MarshalJSON() ([]byte, error) {
	h, e := r.Helper.MarshalJSON()
	if e != nil {
		fmt.Println("sr1 marshal failed @ helper:", e)
		return nil, e
	}
	r1, e := json.Marshal(map[string]interface{}{
		"PublicKey":      r.PublicKey,
		"SecretECDSA":    r.SecretECDSA,
		"SecretPaillier": r.SecretPaillier,
		"Paillier":       r.Paillier,
		"Pedersen":       r.Pedersen,
		"ECDSA":          r.ECDSA,
		"Message":        r.Message,
	})
	if e != nil {
		fmt.Println("sr1 marshal failed @ r1:", e)
		return nil, e
	}
	return jsontools.JoinJSON(r1, h)
}

func (r *Sround1) UnmarshalJSON(j []byte) error {
	var tmp map[string]json.RawMessage
	if err := json.Unmarshal(j, &tmp); err != nil {
		fmt.Println("sr1 unmarshal failed @ tmp:", err)
		return err
	}

	var publickey curve.Point
	var publickey256k1 curve.Secp256k1Point
	if err := json.Unmarshal(tmp["PublicKey"], &publickey256k1); err != nil {
		fmt.Println("sr1 unmarshal failed @ publickey256k1:", err)
		return err
	}
	publickey = &publickey256k1

	var secretEcdsa curve.Scalar
	var secretEcdsa256k1 curve.Secp256k1Scalar
	if err := json.Unmarshal(tmp["SecretECDSA"], &secretEcdsa256k1); err != nil {
		fmt.Println("sr1 unmarshal failed @ secretEcdsa256k1:", err)
		return err
	}
	secretEcdsa = &secretEcdsa256k1

	var pailliersecret *paillier.SecretKey
	if err := json.Unmarshal(tmp["SecretPaillier"], &pailliersecret); err != nil {
		fmt.Println("sr1 unmarshal failed @ pailliersecret:", err)
		return err
	}

	pailliers := make(map[party.ID]*paillier.PublicKey)
	if err := json.Unmarshal(tmp["Paillier"], &pailliers); err != nil {
		fmt.Println("sr1 unmarshal failed @ pailliers:", err)
		return err
	}

	pedersens := make(map[party.ID]*pedersen.Parameters)
	if err := json.Unmarshal(tmp["Pedersen"], &pedersens); err != nil {
		fmt.Println("sr1 unmarshal failed @ pedersens:", err)
		return err
	}

	ecdsas := make(map[party.ID]curve.Point)
	ecdsas256k1 := make(map[party.ID]curve.Secp256k1Point)
	if err := json.Unmarshal(tmp["ECDSA"], &ecdsas256k1); err != nil {
		fmt.Println("sr1 unmarshal failed @ ecdsas256k1:", err)
		return err
	}
	for k, v := range ecdsas256k1 {
		v := v
		ecdsas[k] = &v
	}

	var message []byte
	if err := json.Unmarshal(tmp["Message"], &message); err != nil {
		fmt.Println("sr1 unmarshal failed @ message:", err)
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

	r.PublicKey = publickey
	r.SecretECDSA = secretEcdsa
	r.SecretPaillier = pailliersecret
	r.Paillier = pailliers
	r.Pedersen = pedersens
	r.ECDSA = ecdsas
	r.Message = message
	return nil
}
