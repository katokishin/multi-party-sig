package paillier

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/cronokirby/safenum"
	"github.com/taurusgroup/multi-party-sig/internal/params"
	"github.com/taurusgroup/multi-party-sig/pkg/math/arith"
	"github.com/taurusgroup/multi-party-sig/pkg/math/sample"
	"github.com/taurusgroup/multi-party-sig/pkg/pedersen"
	"github.com/taurusgroup/multi-party-sig/pkg/pool"
)

var (
	ErrPrimeBadLength = errors.New("prime factor is not the right length")
	ErrNotBlum        = errors.New("prime factor is not equivalent to 3 (mod 4)")
	ErrNotSafePrime   = errors.New("supposed prime factor is not a safe prime")
	ErrPrimeNil       = errors.New("prime is nil")
)

// SecretKey is the secret key corresponding to a Public Paillier Key.
//
// A public key is a modulus N, and the secret key contains the information
// needed to factor N into two primes, P and Q. This allows us to decrypt
// values encrypted using this modulus.
type SecretKey struct {
	*PublicKey
	// p, q such that N = p⋅q
	Pv, Qv *safenum.Nat
	// phi = ϕ = (p-1)(q-1)
	Phiv *safenum.Nat
	// phiInv = ϕ⁻¹ mod N
	PhiInv *safenum.Nat
}

// P returns the first of the two factors composing this key.
func (sk *SecretKey) P() *safenum.Nat {
	return sk.Pv
}

// Q returns the second of the two factors composing this key.
func (sk *SecretKey) Q() *safenum.Nat {
	return sk.Qv
}

// Phi returns ϕ = (P-1)(Q-1).
//
// This is the result of the totient function ϕ(N), where N = P⋅Q
// is our public key. This function counts the number of units mod N.
//
// This quantity is useful in ZK proofs.
func (sk *SecretKey) Phi() *safenum.Nat {
	return sk.Phiv
}

// KeyGen generates a new PublicKey and it's associated SecretKey.
func KeyGen(pl *pool.Pool) (pk *PublicKey, sk *SecretKey) {
	sk = NewSecretKey(pl)
	pk = sk.PublicKey
	return
}

// NewSecretKey generates primes p and q suitable for the scheme, and returns the initialized SecretKey.
func NewSecretKey(pl *pool.Pool) *SecretKey {
	// TODO maybe we could take the reader as argument?
	return NewSecretKeyFromPrimes(sample.Paillier(rand.Reader, pl))
}

// NewSecretKeyFromPrimes generates a new SecretKey. Assumes that P and Q are prime.
func NewSecretKeyFromPrimes(P, Q *safenum.Nat) *SecretKey {
	oneNat := new(safenum.Nat).SetUint64(1)

	n := arith.ModulusFromFactors(P, Q)

	nNat := n.Nat()
	nPlusOne := new(safenum.Nat).Add(nNat, oneNat, -1)
	// Tightening is fine, since n is public
	nPlusOne.Resize(nPlusOne.TrueLen())

	pMinus1 := new(safenum.Nat).Sub(P, oneNat, -1)
	qMinus1 := new(safenum.Nat).Sub(Q, oneNat, -1)
	phi := new(safenum.Nat).Mul(pMinus1, qMinus1, -1)
	// ϕ⁻¹ mod N
	phiInv := new(safenum.Nat).ModInverse(phi, n.Modulus)

	pSquared := pMinus1.Mul(P, P, -1)
	qSquared := qMinus1.Mul(Q, Q, -1)
	nSquared := arith.ModulusFromFactors(pSquared, qSquared)

	return &SecretKey{
		Pv:     P,
		Qv:     Q,
		Phiv:   phi,
		PhiInv: phiInv,
		PublicKey: &PublicKey{
			Nv:       n,
			NSquared: nSquared,
			NNat:     nNat,
			NPlusOne: nPlusOne,
		},
	}
}

// Dec decrypts c and returns the plaintext m ∈ ± (N-2)/2.
// It returns an error if gcd(c, N²) != 1 or if c is not in [1, N²-1].
func (sk *SecretKey) Dec(ct *Ciphertext) (*safenum.Int, error) {
	oneNat := new(safenum.Nat).SetUint64(1)

	n := sk.PublicKey.Nv.Modulus

	if !sk.PublicKey.ValidateCiphertexts(ct) {
		return nil, errors.New("paillier: failed to decrypt invalid ciphertext")
	}

	phi := sk.Phiv
	phiInv := sk.PhiInv

	// r = c^Phi 						(mod N²)
	result := sk.PublicKey.NSquared.Exp(ct.C, phi)
	// r = c^Phi - 1
	result.Sub(result, oneNat, -1)
	// r = [(c^Phi - 1)/N]
	result.Div(result, n, -1)
	// r = [(c^Phi - 1)/N] • Phi^-1		(mod N)
	result.ModMul(result, phiInv, n)

	// see 6.1 https://www.iacr.org/archive/crypto2001/21390136.pdf
	return new(safenum.Int).SetModSymmetric(result, n), nil
}

// DecWithRandomness returns the underlying plaintext, as well as the randomness used.
func (sk *SecretKey) DecWithRandomness(ct *Ciphertext) (*safenum.Int, *safenum.Nat, error) {
	m, err := sk.Dec(ct)
	if err != nil {
		return nil, nil, err
	}
	mNeg := new(safenum.Int).SetInt(m).Neg(1)

	// x = C(N+1)⁻ᵐ (mod N)
	x := sk.Nv.ExpI(sk.NPlusOne, mNeg)
	x.ModMul(x, ct.C, sk.Nv.Modulus)

	// r = xⁿ⁻¹ (mod N)
	nInverse := new(safenum.Nat).ModInverse(sk.NNat, safenum.ModulusFromNat(sk.Phiv))
	r := sk.Nv.Exp(x, nInverse)
	return m, r, nil
}

func (sk SecretKey) GeneratePedersen() (*pedersen.Parameters, *safenum.Nat) {
	s, t, lambda := sample.Pedersen(rand.Reader, sk.Phiv, sk.Nv.Modulus)
	ped := pedersen.New(sk.Nv, s, t)
	return ped, lambda
}

// ValidatePrime checks whether p is a suitable prime for Paillier.
// Checks:
// - log₂(p) ≡ params.BitsBlumPrime.
// - p ≡ 3 (mod 4).
// - q := (p-1)/2 is prime.
func ValidatePrime(p *safenum.Nat) error {
	if p == nil {
		return ErrPrimeNil
	}
	// check bit lengths
	const bitsWant = params.BitsBlumPrime
	// Technically, this leaks the number of bits, but this is fine, since returning
	// an error asserts this number statically, anyways.
	if bits := p.TrueLen(); bits != bitsWant {
		return fmt.Errorf("invalid prime size: have: %d, need %d: %w", bits, bitsWant, ErrPrimeBadLength)
	}
	// check == 3 (mod 4)
	if p.Byte(0)&0b11 != 3 {
		return ErrNotBlum
	}

	// check (p-1)/2 is prime
	pMinus1Div2 := new(safenum.Nat).Rsh(p, 1, -1)

	if !pMinus1Div2.Big().ProbablyPrime(1) {
		return ErrNotSafePrime
	}
	return nil
}

func (sk SecretKey) MarshalJSON() ([]byte, error) {
	return json.Marshal(map[string]interface{}{
		"PublicKey": sk.PublicKey,
		"Pv":        sk.Pv.Bytes(),
		"Qv":        sk.Qv.Bytes(),
		"Phiv":      sk.Phiv.Bytes(),
		"PhiInv":    sk.PhiInv.Bytes(),
	})
}

func (sk *SecretKey) UnmarshalJSON(j []byte) error {
	var tmp map[string]json.RawMessage
	if e := json.Unmarshal(j, &tmp); e != nil {
		fmt.Println("pailler secret key unmarshal failed @ tmp:", e)
		return e
	}

	var pubkey PublicKey
	if e := json.Unmarshal(tmp["PublicKey"], &pubkey); e != nil {
		fmt.Println("pailler secret key unmarshal failed @ publickey:", e)
		return e
	}
	sk.PublicKey = &pubkey

	var pv safenum.Nat
	tmpstr := string(tmp["Pv"][1 : len(tmp["Pv"])-1])
	decode, _ := base64.StdEncoding.DecodeString(tmpstr)
	pvbytes := []byte(decode)
	pv.SetBytes(pvbytes)
	sk.Pv = &pv

	var qv safenum.Nat
	tmpstr = string(tmp["Qv"][1 : len(tmp["Qv"])-1])
	decode, _ = base64.StdEncoding.DecodeString(tmpstr)
	qvbytes := []byte(decode)
	qv.SetBytes(qvbytes)
	sk.Qv = &qv

	var phiv safenum.Nat
	tmpstr = string(tmp["Phiv"][1 : len(tmp["Phiv"])-1])
	decode, _ = base64.StdEncoding.DecodeString(tmpstr)
	phivbytes := []byte(decode)
	phiv.SetBytes(phivbytes)
	sk.Phiv = &phiv

	var phiinv safenum.Nat
	tmpstr = string(tmp["PhiInv"][1 : len(tmp["PhiInv"])-1])
	decode, _ = base64.StdEncoding.DecodeString(tmpstr)
	phiinvbytes := []byte(decode)
	phiinv.SetBytes(phiinvbytes)
	sk.PhiInv = &phiinv

	return nil
}
