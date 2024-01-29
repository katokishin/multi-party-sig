package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"strconv"
	"strings"

	"github.com/taurusgroup/multi-party-sig/internal/bip32"
	"github.com/taurusgroup/multi-party-sig/internal/params"
	"github.com/taurusgroup/multi-party-sig/internal/types"
	"github.com/taurusgroup/multi-party-sig/pkg/math/curve"
	"github.com/taurusgroup/multi-party-sig/pkg/math/polynomial"
	"github.com/taurusgroup/multi-party-sig/pkg/paillier"
	"github.com/taurusgroup/multi-party-sig/pkg/party"
	"github.com/taurusgroup/multi-party-sig/pkg/pedersen"
)

// Config contains all necessary cryptographic keys necessary to generate a signature.
// It also represents the `SSID` after having performed a keygen/refresh operation.
// where SSID = (𝔾, t, n, P₁, …, Pₙ, (X₁, Y₁, N₁, s₁, t₁), …, (Xₙ, Yₙ, Nₙ, sₙ, tₙ)).
//
// To unmarshal this struct, EmptyConfig should be called first with a specific group,
// before using cbor.Unmarshal with that struct.
type Config struct {
	// Group returns the Elliptic Curve Group associated with this config.
	Group curve.Curve
	// ID is the identifier of the party this Config belongs to.
	ID party.ID
	// Threshold is the integer t which defines the maximum number of corruptions tolerated for this config.
	// Threshold + 1 is the minimum number of parties' shares required to reconstruct the secret/sign a message.
	Threshold int
	// ECDSA is this party's share xᵢ of the secret ECDSA x.
	ECDSA curve.Scalar
	// ElGamal is this party's yᵢ used for ElGamal.
	ElGamal curve.Scalar
	// Paillier is this party's Paillier decryption key.
	Paillier *paillier.SecretKey
	// RID is a 32 byte random identifier generated for this config
	RID types.RID
	// ChainKey is the chaining key value associated with this public key
	ChainKey types.RID
	// Public maps party.ID to public. It contains all public information associated to a party.
	Public map[party.ID]*Public
}

// Public holds public information for a party.
type Public struct {
	// ECDSA public key share
	ECDSA curve.Point
	// ElGamal is this party's public key for ElGamal encryption.
	ElGamal curve.Point
	// Paillier is this party's public Paillier key.
	Paillier *paillier.PublicKey
	// Pedersen is this party's public Pedersen parameters.
	Pedersen *pedersen.Parameters
}

// PublicPoint returns the group's public ECC point.
func (c *Config) PublicPoint() curve.Point {
	sum := c.Group.NewPoint()
	partyIDs := make([]party.ID, 0, len(c.Public))
	for j := range c.Public {
		partyIDs = append(partyIDs, j)
	}
	l := polynomial.Lagrange(c.Group, partyIDs)
	for j, partyJ := range c.Public {
		sum = sum.Add(l[j].Act(partyJ.ECDSA))
	}
	return sum
}

// PartyIDs returns a sorted slice of party IDs.
func (c *Config) PartyIDs() party.IDSlice {
	ids := make([]party.ID, 0, len(c.Public))
	for j := range c.Public {
		ids = append(ids, j)
	}
	return party.NewIDSlice(ids)
}

// WriteTo implements io.WriterTo interface.
func (c *Config) WriteTo(w io.Writer) (total int64, err error) {
	if c == nil {
		return 0, io.ErrUnexpectedEOF
	}
	var n int64

	// write t
	n, err = types.ThresholdWrapper(c.Threshold).WriteTo(w)
	total += n
	if err != nil {
		return
	}

	// write partyIDs
	partyIDs := c.PartyIDs()
	n, err = partyIDs.WriteTo(w)
	total += n
	if err != nil {
		return
	}

	// write rid
	n, err = c.RID.WriteTo(w)
	total += n
	if err != nil {
		return
	}

	// write all party data
	for _, j := range partyIDs {
		// write Xⱼ
		n, err = c.Public[j].WriteTo(w)
		total += n
		if err != nil {
			return
		}
	}
	return
}

// Domain implements hash.WriterToWithDomain.
func (c *Config) Domain() string {
	return "CMP Config"
}

// Domain implements hash.WriterToWithDomain.
func (Public) Domain() string {
	return "Public Data"
}

// WriteTo implements io.WriterTo interface.
func (p *Public) WriteTo(w io.Writer) (total int64, err error) {
	if p == nil {
		return 0, io.ErrUnexpectedEOF
	}
	// write ECDSA
	data, err := p.ECDSA.MarshalBinary()
	if err != nil {
		return
	}
	n, err := w.Write(data)
	total = int64(n)
	if err != nil {
		return
	}

	// write ElGamal
	data, err = p.ElGamal.MarshalBinary()
	if err != nil {
		return
	}
	n, err = w.Write(data)
	total += int64(n)
	if err != nil {
		return
	}

	n64, err := p.Paillier.WriteTo(w)
	total += n64
	if err != nil {
		return
	}

	n64, err = p.Pedersen.WriteTo(w)
	total += n64
	if err != nil {
		return
	}

	return
}

// CanSign returns true if the given _sorted_ list of signers is
// a valid subset of the original parties of size > t,
// and includes self.
func (c *Config) CanSign(signers party.IDSlice) bool {
	if !ValidThreshold(c.Threshold, len(signers)) {
		return false
	}

	// check for duplicates
	if !signers.Valid() {
		return false
	}

	if !signers.Contains(c.ID) {
		return false
	}

	// check that the signers are a subset of the original parties,
	// that it includes self, and that the size is > t.
	for _, j := range signers {
		if _, ok := c.Public[j]; !ok {
			return false
		}
	}

	return true
}

func ValidThreshold(t, n int) bool {
	if t < 0 || t > math.MaxUint32 {
		return false
	}
	if n <= 0 || t > n-1 {
		return false
	}
	return true
}

// Derive adds adjust to the private key, resulting in a new key pair.
//
// This supports arbitrary derivation methods, including BIP32. For explicit
// BIP32 support, see DeriveBIP32.
//
// A new chain key can be passed, which will replace the existing one for the new keypair.
func (c *Config) Derive(adjust curve.Scalar, newChainKey []byte) (*Config, error) {
	if len(newChainKey) <= 0 {
		newChainKey = c.ChainKey
	}
	if len(newChainKey) != params.SecBytes {
		return nil, fmt.Errorf("expecte %d bytes for chain key, found %d", params.SecBytes, len(newChainKey))
	}
	// We need to add the scalar we've derived to the underlying secret,
	// for which it's sufficient to simply add it to each share. This means adding
	// scalar * G to each verification share as well.
	adjustG := adjust.ActOnBase()

	public := make(map[party.ID]*Public, len(c.Public))
	for k, v := range c.Public {
		public[k] = &Public{
			ECDSA:    v.ECDSA.Add(adjustG),
			ElGamal:  v.ElGamal,
			Paillier: v.Paillier,
			Pedersen: v.Pedersen,
		}
	}

	return &Config{
		Group:     c.Group,
		ID:        c.ID,
		Threshold: c.Threshold,
		ECDSA:     c.Group.NewScalar().Set(c.ECDSA).Add(adjust),
		ElGamal:   c.ElGamal,
		Paillier:  c.Paillier,
		RID:       c.RID,
		ChainKey:  newChainKey,
		Public:    public,
	}, nil
}

// DeriveBIP32 derives a sharing of the ith child of the consortium signing key.
//
// This function uses unhardened derivation, deriving a key without including the
// underlying private key. This function will panic if i ⩾ 2³¹, since that indicates
// a hardened key.
//
// Sometimes, an error will be returned, indicating that this index generates
// an invalid key.
//
// See: https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki
func (c *Config) DeriveBIP32(i uint32) (*Config, error) {
	publicPoint, ok := c.PublicPoint().(*curve.Secp256k1Point)
	if !ok {
		return nil, errors.New("DeriveBIP32 must be called with secp256k1")
	}
	scalar, newChainKey, err := bip32.DeriveScalar(publicPoint, c.ChainKey, i)
	if err != nil {
		return nil, err
	}
	return c.Derive(scalar, newChainKey)
}

func (c *Config) DerivePath(path string) (*Config, error) {
	// Check path regex
	// Must be of format "m/k1/k2/k3" where 0 <= k < 2^32
	// CANNOT use hardened key derivation, e.g. where k >= 2^32
	// and represented by an apostrophe e.g. "m/k1'/k2'/k3'"
	pathSlice := strings.Split(path, "/")
	k1, err := strconv.ParseUint(pathSlice[1], 0, 32)

	k2, err := strconv.ParseUint(pathSlice[2], 0, 32)

	k3, err := strconv.ParseUint(pathSlice[3], 0, 32)

	if len(pathSlice) != 4 || pathSlice[0] != "m" {
		return nil, fmt.Errorf("Invalid derivation path")
	}

	// Actual derivation happens like:
	// m.DeriveBIP32(k1).DeriveBIP32(k2).DeriveBIP32(k3)
	derivedConfig, err := c.DeriveBIP32(uint32(k1))
	if err != nil {
		fmt.Println(err)
		return nil, err
	}
	derivedConfig, err = derivedConfig.DeriveBIP32(uint32(k2))
	if err != nil {
		fmt.Println(err)
		return nil, err
	}
	derivedConfig, err = derivedConfig.DeriveBIP32(uint32(k3))
	if err != nil {
		fmt.Println(err)
		return nil, err
	}
	return derivedConfig, err
}

func (c Config) MarshalJSON() ([]byte, error) {
	return json.Marshal(map[string]interface{}{
		"Group":     c.Group,
		"ID":        c.ID,
		"Threshold": c.Threshold,
		"ECDSA":     c.ECDSA,
		"ElGamal":   c.ElGamal,
		"Paillier":  c.Paillier,
		"RID":       c.RID,
		"ChainKey":  c.ChainKey,
		"Public":    c.Public,
	})
}

func (c *Config) UnmarshalJSON(j []byte) error {
	var tmp map[string]json.RawMessage
	if e := json.Unmarshal(j, &tmp); e != nil {
		fmt.Println("Failed to Config.UnmarshalJSON @ tmp:", e)
		return e
	}

	var id party.ID
	if e := json.Unmarshal(tmp["ID"], &id); e != nil {
		fmt.Println("Failed to Config.UnmarshalJSON @ ID:", e)
		return e
	}

	var threshold int
	if e := json.Unmarshal(tmp["Threshold"], &threshold); e != nil {
		fmt.Println("Failed to Config.UnmarshalJSON @ Threshold:", e)
		return e
	}

	var ecdsa curve.Scalar
	var ecdsaSecp256k1 curve.Secp256k1Scalar
	if e := json.Unmarshal(tmp["ECDSA"], &ecdsaSecp256k1); e != nil {
		fmt.Println("Failed to Config.UnmarshalJSON @ ECDSA:", e)
		return e
	}
	ecdsa = &ecdsaSecp256k1

	var elgamal curve.Scalar
	var elgamal256k1 curve.Secp256k1Scalar
	if e := json.Unmarshal(tmp["ElGamal"], &elgamal256k1); e != nil {
		fmt.Println("Failed to Config.UnmarshalJSON @ ElGamal:", e)
		return e
	}
	elgamal = &elgamal256k1

	var paillier *paillier.SecretKey
	if e := json.Unmarshal(tmp["Paillier"], &paillier); e != nil {
		fmt.Println("Failed to Config.UnmarshalJSON @ Paillier:", e)
		return e
	}

	var rid types.RID
	if e := json.Unmarshal(tmp["RID"], &rid); e != nil {
		fmt.Println("Failed to Config.UnmarshalJSON @ RID:", e)
		return e
	}

	var chainkey types.RID
	if e := json.Unmarshal(tmp["ChainKey"], &chainkey); e != nil {
		fmt.Println("Failed to Config.UnmarshalJSON @ ChainKey:", e)
		return e
	}

	publics := make(map[party.ID]*Public)
	publicsJson := make(map[party.ID]json.RawMessage)
	if e := json.Unmarshal(tmp["Public"], &publicsJson); e != nil {
		fmt.Println("Failed to Config.UnmarshalJSON @ Public:", e)
		return e
	}
	for k, v := range publicsJson {
		var p Public
		if e := json.Unmarshal(v, &p); e != nil {
			fmt.Println("Failed to Config.UnmarshalJSON @ Public[k]:", e)
			return e
		}
		publics[k] = &p
	}

	c.Group = curve.Secp256k1{}
	c.ID = id
	c.Threshold = threshold
	c.ECDSA = ecdsa
	c.ElGamal = elgamal
	c.Paillier = paillier
	c.RID = rid
	c.ChainKey = chainkey
	c.Public = publics
	return nil
}

func (p *Public) UnmarshalJSON(j []byte) error {
	var tmp map[string]json.RawMessage
	if e := json.Unmarshal(j, &tmp); e != nil {
		fmt.Println("Failed to Public.UnmarshalJSON @ tmp:", e)
		return e
	}

	var ecdsa curve.Point
	var ecdsaSecp256k1 curve.Secp256k1Point
	if e := json.Unmarshal(tmp["ECDSA"], &ecdsaSecp256k1); e != nil {
		fmt.Println("Failed to Public.UnmarshalJSON @ ECDSA:", e)
		return e
	}
	ecdsa = &ecdsaSecp256k1

	var elgamal curve.Point
	var elgamal256k1 curve.Secp256k1Point
	if e := json.Unmarshal(tmp["ElGamal"], &elgamal256k1); e != nil {
		fmt.Println("Failed to Public.UnmarshalJSON @ ElGamal:", e)
		return e
	}
	elgamal = &elgamal256k1

	var paillier *paillier.PublicKey
	if e := json.Unmarshal(tmp["Paillier"], &paillier); e != nil {
		fmt.Println("Failed to Public.UnmarshalJSON @ Paillier:", e)
		return e
	}

	pedersen := pedersen.Parameters{}
	if e := json.Unmarshal(tmp["Pedersen"], &pedersen); e != nil {
		fmt.Println("Failed to Public.UnmarshalJSON @ Pedersen:", e)
		return e
	}

	p.ECDSA = ecdsa
	p.ElGamal = elgamal
	p.Paillier = paillier
	p.Pedersen = &pedersen
	return nil
}
