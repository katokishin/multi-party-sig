package paillier

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"

	"github.com/cronokirby/safenum"
	"github.com/taurusgroup/multi-party-sig/internal/params"
	"github.com/taurusgroup/multi-party-sig/pkg/math/arith"
	"github.com/taurusgroup/multi-party-sig/pkg/math/sample"
)

var (
	ErrPaillierLength = errors.New("wrong number bit length of Paillier modulus N")
	ErrPaillierEven   = errors.New("modulus N is even")
	ErrPaillierNil    = errors.New("modulus N is nil")
)

// PublicKey is a Paillier public key. It is represented by a modulus N.
type PublicKey struct {
	// n = p⋅q
	Nv *arith.Modulus
	// nSquared = n²
	NSquared *arith.Modulus

	// These values are cached out of convenience, and performance
	NNat *safenum.Nat
	// nPlusOne = n + 1
	NPlusOne *safenum.Nat
}

// N is the public modulus making up this key.
func (pk *PublicKey) N() *safenum.Modulus {
	return pk.Nv.Modulus
}

// NewPublicKey returns an initialized paillier.PublicKey and caches N, N² and (N-1)/2.
func NewPublicKey(n *safenum.Modulus) *PublicKey {
	oneNat := new(safenum.Nat).SetUint64(1)
	nNat := n.Nat()
	nSquared := safenum.ModulusFromNat(new(safenum.Nat).Mul(nNat, nNat, -1))
	nPlusOne := new(safenum.Nat).Add(nNat, oneNat, -1)
	// Tightening is fine, since n is public
	nPlusOne.Resize(nPlusOne.TrueLen())

	return &PublicKey{
		Nv:       arith.ModulusFromN(n),
		NSquared: arith.ModulusFromN(nSquared),
		NNat:     nNat,
		NPlusOne: nPlusOne,
	}
}

// ValidateN performs basic checks to make sure the modulus is valid:
// - log₂(n) = params.BitsPaillier.
// - n is odd.
func ValidateN(n *safenum.Modulus) error {
	if n == nil {
		return ErrPaillierNil
	}
	// log₂(N) = BitsPaillier
	nBig := n.Big()
	if bits := nBig.BitLen(); bits != params.BitsPaillier {
		return fmt.Errorf("have: %d, need %d: %w", bits, params.BitsPaillier, ErrPaillierLength)
	}
	if nBig.Bit(0) != 1 {
		return ErrPaillierEven
	}
	return nil
}

// Enc returns the encryption of m under the public key pk.
// The nonce used to encrypt is returned.
//
// The message m must be in the range [-(N-1)/2, …, (N-1)/2] and panics otherwise.
//
// ct = (1+N)ᵐρᴺ (mod N²).
func (pk PublicKey) Enc(m *safenum.Int) (*Ciphertext, *safenum.Nat) {
	nonce := sample.UnitModN(rand.Reader, pk.Nv.Modulus)
	return pk.EncWithNonce(m, nonce), nonce
}

// EncWithNonce returns the encryption of m under the public key pk.
// The nonce is not returned.
//
// The message m must be in the range [-(N-1)/2, …, (N-1)/2] and panics otherwise
//
// ct = (1+N)ᵐρᴺ (mod N²).
func (pk PublicKey) EncWithNonce(m *safenum.Int, nonce *safenum.Nat) *Ciphertext {
	mAbs := m.Abs()
	nHalf := new(safenum.Nat).SetNat(pk.NNat)
	nHalf.Rsh(nHalf, 1, -1)
	if gt, _, _ := mAbs.Cmp(nHalf); gt == 1 {
		panic("paillier.Encrypt: tried to encrypt message outside of range [-(N-1)/2, …, (N-1)/2]")
	}

	// (N+1)ᵐ mod N²
	c := pk.NSquared.ExpI(pk.NPlusOne, m)
	// ρᴺ mod N²
	rhoN := pk.NSquared.Exp(nonce, pk.NNat)
	// (N+1)ᵐ rho ^ N
	c.ModMul(c, rhoN, pk.NSquared.Modulus)

	return &Ciphertext{C: c}
}

// Equal returns true if pk ≡ other.
func (pk PublicKey) Equal(other *PublicKey) bool {
	_, eq, _ := pk.Nv.Cmp(other.Nv.Modulus)
	return eq == 1
}

// ValidateCiphertexts checks if all ciphertexts are in the correct range and coprime to N²
// ct ∈ [1, …, N²-1] AND GCD(ct,N²) = 1.
func (pk PublicKey) ValidateCiphertexts(cts ...*Ciphertext) bool {
	for _, ct := range cts {
		if ct == nil {
			return false
		}
		_, _, lt := ct.C.CmpMod(pk.NSquared.Modulus)
		if lt != 1 {
			return false
		}
		if ct.C.IsUnit(pk.NSquared.Modulus) != 1 {
			return false
		}
	}
	return true
}

// WriteTo implements io.WriterTo and should be used within the hash.Hash function.
func (pk *PublicKey) WriteTo(w io.Writer) (int64, error) {
	if pk == nil {
		return 0, io.ErrUnexpectedEOF
	}
	buf := pk.Nv.Bytes()
	n, err := w.Write(buf)
	return int64(n), err
}

// Domain implements hash.WriterToWithDomain, and separates this type within hash.Hash.
func (PublicKey) Domain() string {
	return "Paillier PublicKey"
}

// Modulus returns an arith.Modulus for N which may allow for accelerated exponentiation when this
// public key was generated from a secret key.
func (pk *PublicKey) Modulus() *arith.Modulus {
	return pk.Nv
}

// ModulusSquared returns an arith.Modulus for N² which may allow for accelerated exponentiation when this
// public key was generated from a secret key.
func (pk *PublicKey) ModulusSquared() *arith.Modulus {
	return pk.NSquared
}

func (p PublicKey) MarshalJSON() ([]byte, error) {
	/*
		nstr, e := p.Nv.MarshalBinary()
		if e != nil {
			fmt.Println(e)
			return nil, e
		}
		nsqrd, e := p.NSquared.MarshalBinary()
		if e != nil {
			fmt.Println(e)
			return nil, e
		}
		nnat, e := p.NNat.MarshalBinary()
		if e != nil {
			fmt.Println(e)
			return nil, e
		}
		nplone, e := p.NPlusOne.MarshalBinary()
		if e != nil {
			fmt.Println(e)
			return nil, e
		}
	*/
	nvb, _ := p.Nv.MarshalBinary()
	nsb, _ := p.NSquared.MarshalBinary()
	nnb, _ := p.NNat.MarshalBinary()
	npb, _ := p.NPlusOne.MarshalBinary()
	j, e := json.Marshal(map[string]interface{}{
		"Nv":       base64.StdEncoding.EncodeToString(nvb),
		"NSquared": base64.StdEncoding.EncodeToString(nsb),
		"NNat":     base64.StdEncoding.EncodeToString(nnb),
		"NPlusOne": base64.StdEncoding.EncodeToString(npb),
	})
	return j, e
}

func (p *PublicKey) UnmarshalJSON(j []byte) error {
	var tmp map[string]json.RawMessage
	if e := json.Unmarshal(j, &tmp); e != nil {
		fmt.Println("pailler public key unmarshal failed @ tmp:", e)
		return e
	}

	var tmpstr = string(tmp["Nv"][1 : len(tmp["Nv"])-1])
	decode, _ := base64.StdEncoding.DecodeString(tmpstr)
	nbytes := []byte(decode)
	n := arith.Modulus{Modulus: safenum.ModulusFromBytes(nbytes)}
	e := n.Modulus.UnmarshalBinary(nbytes)
	if e != nil {
		fmt.Println("artih.Modulus.UnmarshalBinary failed @ nv:", e)
		return e
	}
	p.Nv = &n

	tmpstr = string(tmp["NSquared"][1 : len(tmp["NSquared"])-1])
	decode, _ = base64.StdEncoding.DecodeString(tmpstr)
	nsqbytes := []byte(decode)
	nSquared := arith.Modulus{Modulus: safenum.ModulusFromBytes(nsqbytes)}
	e = nSquared.UnmarshalBinary(nsqbytes)
	if e != nil {
		fmt.Println("artih.Modulus.UnmarshalBinary failed @ nsq:", e)
		return e
	}
	p.NSquared = &nSquared

	var nNat safenum.Nat
	tmpstr = string(tmp["NNat"][1 : len(tmp["NNat"])-1])
	decode, _ = base64.StdEncoding.DecodeString(tmpstr)
	nnatbytes := []byte(decode)
	nNat.SetBytes(nnatbytes)
	p.NNat = &nNat

	var nPlusOne safenum.Nat
	tmpstr = string(tmp["NPlusOne"][1 : len(tmp["NPlusOne"])-1])
	decode, _ = base64.StdEncoding.DecodeString(tmpstr)
	npobytes := []byte(decode)
	nPlusOne.SetBytes(npobytes)
	p.NPlusOne = &nPlusOne
	return nil
}
