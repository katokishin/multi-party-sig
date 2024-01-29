package sign

import (
	"encoding/json"
	"errors"
	"fmt"

	"github.com/cronokirby/safenum"
	"github.com/taurusgroup/multi-party-sig/internal/jsontools"
	"github.com/taurusgroup/multi-party-sig/internal/mta"
	"github.com/taurusgroup/multi-party-sig/internal/round"
	"github.com/taurusgroup/multi-party-sig/pkg/math/curve"
	"github.com/taurusgroup/multi-party-sig/pkg/paillier"
	"github.com/taurusgroup/multi-party-sig/pkg/party"
	zkenc "github.com/taurusgroup/multi-party-sig/pkg/zk/enc"
	zklogstar "github.com/taurusgroup/multi-party-sig/pkg/zk/logstar"
)

var _ round.Round = (*Sround2)(nil)

type Sround2 struct {
	*Sround1

	// K[j] = Kⱼ = encⱼ(kⱼ)
	K map[party.ID]*paillier.Ciphertext
	// G[j] = Gⱼ = encⱼ(γⱼ)
	G map[party.ID]*paillier.Ciphertext

	// BigGammaShare[j] = Γⱼ = [γⱼ]•G
	BigGammaShare map[party.ID]curve.Point

	// GammaShare = γᵢ <- 𝔽
	GammaShare *safenum.Int
	// KShare = kᵢ  <- 𝔽
	KShare curve.Scalar

	// KNonce = ρᵢ <- ℤₙ
	// used to encrypt Kᵢ = Encᵢ(kᵢ)
	KNonce *safenum.Nat
	// GNonce = νᵢ <- ℤₙ
	// used to encrypt Gᵢ = Encᵢ(γᵢ)
	GNonce *safenum.Nat
}

type broadcast2 struct {
	round.ReliableBroadcastContent
	// K = Kᵢ
	K *paillier.Ciphertext
	// G = Gᵢ
	G *paillier.Ciphertext
}

type message2 struct {
	ProofEnc *zkenc.Proof
}

// StoreBroadcastMessage implements round.Round.
//
// - store Kⱼ, Gⱼ.
func (r *Sround2) StoreBroadcastMessage(msg round.Message) error {
	from := msg.From
	body, ok := msg.Content.(*broadcast2)
	if !ok || body == nil {
		return round.ErrInvalidContent
	}

	if !r.Paillier[from].ValidateCiphertexts(body.K, body.G) {
		return errors.New("invalid K, G")
	}

	r.K[from] = body.K
	r.G[from] = body.G

	return nil
}

// VerifyMessage implements round.Round.
//
// - verify zkenc(Kⱼ).
func (r *Sround2) VerifyMessage(msg round.Message) error {
	from, to := msg.From, msg.To
	body, ok := msg.Content.(*message2)
	if !ok || body == nil {
		return round.ErrInvalidContent
	}

	if body.ProofEnc == nil {
		return round.ErrNilFields
	}

	if !body.ProofEnc.Verify(r.Group(), r.HashForID(from), zkenc.Public{
		K:      r.K[from],
		Prover: r.Paillier[from],
		Aux:    r.Pedersen[to],
	}) {
		return errors.New("failed to validate enc proof for K")
	}
	return nil
}

// StoreMessage implements round.Round.
//
// - store Kⱼ, Gⱼ.
func (Sround2) StoreMessage(round.Message) error { return nil }

// Finalize implements round.Round
//
// - compute Hash(ssid, K₁, G₁, …, Kₙ, Gₙ).
func (r *Sround2) Finalize(out []*round.Message) (round.Session, []*round.Message, error) {
	out = r.BroadcastMessage(out, &broadcast3{
		BigGammaShare: r.BigGammaShare[r.SelfID()],
	})

	otherIDs := r.OtherPartyIDs()
	type mtaOut struct {
		err       error
		DeltaBeta *safenum.Int
		ChiBeta   *safenum.Int
	}
	mtaOuts := r.Pool.Parallelize(len(otherIDs), func(i int) interface{} {
		j := otherIDs[i]

		DeltaBeta, DeltaD, DeltaF, DeltaProof := mta.ProveAffG(r.Group(), r.HashForID(r.SelfID()),
			r.GammaShare, r.BigGammaShare[r.SelfID()], r.K[j],
			r.SecretPaillier, r.Paillier[j], r.Pedersen[j])
		ChiBeta, ChiD, ChiF, ChiProof := mta.ProveAffG(r.Group(),
			r.HashForID(r.SelfID()), curve.MakeInt(r.SecretECDSA), r.ECDSA[r.SelfID()], r.K[j],
			r.SecretPaillier, r.Paillier[j], r.Pedersen[j])

		proof := zklogstar.NewProof(r.Group(), r.HashForID(r.SelfID()),
			zklogstar.Public{
				C:      r.G[r.SelfID()],
				X:      r.BigGammaShare[r.SelfID()],
				Prover: r.Paillier[r.SelfID()],
				Aux:    r.Pedersen[j],
			}, zklogstar.Private{
				X:   r.GammaShare,
				Rho: r.GNonce,
			})
		out = r.SendMessage(out, &message3{
			DeltaD:     DeltaD,
			DeltaF:     DeltaF,
			DeltaProof: DeltaProof,
			ChiD:       ChiD,
			ChiF:       ChiF,
			ChiProof:   ChiProof,
			ProofLog:   proof,
		}, j)
		return mtaOut{
			err:       nil,
			DeltaBeta: DeltaBeta,
			ChiBeta:   ChiBeta,
		}
	})
	DeltaShareBetas := make(map[party.ID]*safenum.Int, len(otherIDs)-1)
	ChiShareBetas := make(map[party.ID]*safenum.Int, len(otherIDs)-1)
	for idx, mtaOutRaw := range mtaOuts {
		j := otherIDs[idx]
		m := mtaOutRaw.(mtaOut)
		if m.err != nil {
			return r, nil, m.err
		}
		DeltaShareBetas[j] = m.DeltaBeta
		ChiShareBetas[j] = m.ChiBeta
	}

	return &Sround3{
		Sround2:         r,
		DeltaShareBeta:  DeltaShareBetas,
		ChiShareBeta:    ChiShareBetas,
		DeltaShareAlpha: map[party.ID]*safenum.Int{},
		ChiShareAlpha:   map[party.ID]*safenum.Int{},
	}, out, nil
}

// RoundNumber implements round.Content.
func (message2) RoundNumber() round.Number { return 2 }

// MessageContent implements round.Round.
func (Sround2) MessageContent() round.Content { return &message2{} }

// RoundNumber implements round.Content.
func (broadcast2) RoundNumber() round.Number { return 2 }

// BroadcastContent implements round.BroadcastRound.
func (Sround2) BroadcastContent() round.BroadcastContent { return &broadcast2{} }

// Number implements round.Round.
func (Sround2) Number() round.Number { return 2 }

func (r *Sround2) MarshalJSON() ([]byte, error) {
	gsb, e := r.GammaShare.MarshalBinary()
	if e != nil {
		fmt.Println(e)
		return nil, e
	}
	knb, e := r.KNonce.MarshalBinary()
	if e != nil {
		fmt.Println(e)
		return nil, e
	}
	gnb, e := r.GNonce.MarshalBinary()
	if e != nil {
		fmt.Println(e)
		return nil, e
	}

	kmap := make(map[party.ID][]byte)
	for k, v := range r.K {
		v := v
		bytes, e := v.MarshalBinary()
		if e != nil {
			fmt.Println("sr2 marshal failed @ kmap:", e)
			return nil, e
		}
		kmap[k] = bytes
	}

	gmap := make(map[party.ID][]byte)
	for k, v := range r.G {
		v := v
		bytes, e := v.MarshalBinary()
		if e != nil {
			fmt.Println("sr2 marshal failed @ gmap:", e)
			return nil, e
		}
		gmap[k] = bytes
	}

	sr2, e := json.Marshal(map[string]interface{}{
		"K":             kmap,
		"G":             gmap,
		"BigGammaShare": r.BigGammaShare,
		"GammaShare":    gsb,
		"KShare":        r.KShare,
		"KNonce":        knb,
		"GNonce":        gnb,
	})
	if e != nil {
		fmt.Println(e)
		return nil, e
	}
	sr1, e := json.Marshal(r.Sround1)
	if e != nil {
		fmt.Println(e)
		return nil, e
	}
	return jsontools.JoinJSON(sr2, sr1)
}

func (r *Sround2) UnmarshalJSON(j []byte) error {
	var tmp map[string]json.RawMessage
	if err := json.Unmarshal(j, &tmp); err != nil {
		fmt.Println("sr2 unmarshal failed @ tmp:", err)
		return err
	}

	var r1 *Sround1
	if err := json.Unmarshal(j, &r1); err != nil {
		fmt.Println("sr2 unmarshal failed @ sr1:", err)
		return err
	}
	r.Sround1 = r1

	kmapBytes := make(map[party.ID][]byte)
	kmap := make(map[party.ID]*paillier.Ciphertext)
	if err := json.Unmarshal(tmp["K"], &kmapBytes); err != nil {
		fmt.Println("sr2 unmarshal failed @ k:", err)
		return err
	}
	for k, v := range kmapBytes {
		v := v
		cipher := new(paillier.Ciphertext)
		err := cipher.UnmarshalBinary(v)
		if err != nil {
			fmt.Println("sr2 unmarshal failed @ kmapBytes to k:", err)
			return err
		}
		kmap[k] = cipher
	}
	r.K = kmap

	gmapBytes := make(map[party.ID][]byte)
	gmap := make(map[party.ID]*paillier.Ciphertext)
	if err := json.Unmarshal(tmp["G"], &gmapBytes); err != nil {
		fmt.Println("sr2 unmarshal failed @ g:", err)
		return err
	}
	for k, v := range gmapBytes {
		v := v
		cipher := new(paillier.Ciphertext)
		err := cipher.UnmarshalBinary(v)
		if err != nil {
			fmt.Println("sr2 unmarshal failed @ gmapBytes to g:", err)
			return err
		}
		gmap[k] = cipher
	}
	r.G = gmap

	biggammas := make(map[party.ID]curve.Point)
	biggammas256k1 := make(map[party.ID]curve.Secp256k1Point)
	if err := json.Unmarshal(tmp["BigGammaShare"], &biggammas256k1); err != nil {
		fmt.Println("sr2 unmarshal failed @ BigGammaShare:", err)
		return err
	}
	for k, v := range biggammas256k1 {
		v := v
		biggammas[k] = &v
	}
	r.BigGammaShare = biggammas

	var gammashareBytes []byte
	gammashare := *&safenum.Int{}
	if err := json.Unmarshal(tmp["GammaShare"], &gammashareBytes); err != nil {
		fmt.Println("sr2 unmarshal failed @ GammaShare:", err)
		return err
	}
	if err := gammashare.UnmarshalBinary(gammashareBytes); err != nil {
		fmt.Println("sr2 unmarshal failed @ gammashare unmarshalbinary:", err)
		return err
	}
	r.GammaShare = &gammashare

	var kshare curve.Scalar
	var kshare256k1 curve.Secp256k1Scalar
	if err := json.Unmarshal(tmp["KShare"], &kshare256k1); err != nil {
		fmt.Println("sr2 unmarshal failed @ kshare:", err)
		return err
	}
	kshare = &kshare256k1
	r.KShare = kshare

	var knonceBytes []byte
	knonce := *&safenum.Modulus{}
	if err := json.Unmarshal(tmp["KNonce"], &knonceBytes); err != nil {
		fmt.Println("sr2 unmarshal failed @ knonce:", err)
		return err
	}
	if e := knonce.UnmarshalBinary(knonceBytes); e != nil {
		fmt.Println("sr2 unmarshal failed @ unmarshalBinary(knonce)")
		return e
	}
	r.KNonce = knonce.Nat()

	var gnonceBytes []byte
	gnonce := *&safenum.Modulus{}
	if err := json.Unmarshal(tmp["GNonce"], &gnonceBytes); err != nil {
		fmt.Println("sr2 unmarshal failed @ gnonce:", err)
		return err
	}
	if e := gnonce.UnmarshalBinary(gnonceBytes); e != nil {
		fmt.Println("sr2 unmarshal failed @ unmarshalBinary(gnonce)")
		return e
	}
	r.GNonce = gnonce.Nat()

	return nil
}
