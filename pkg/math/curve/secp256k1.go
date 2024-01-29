package curve

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/cronokirby/safenum"
	"github.com/decred/dcrd/dcrec/secp256k1/v3"
)

var secp256k1BaseX, secp256k1BaseY secp256k1.FieldVal

func init() {
	Gx, _ := hex.DecodeString("79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798")
	Gy, _ := hex.DecodeString("483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8")
	secp256k1BaseX.SetByteSlice(Gx)
	secp256k1BaseY.SetByteSlice(Gy)
}

type Secp256k1 struct{}

func (Secp256k1) NewPoint() Point {
	return new(Secp256k1Point)
}

func (Secp256k1) NewBasePoint() Point {
	out := new(Secp256k1Point)
	out.Value.X.Set(&secp256k1BaseX)
	out.Value.Y.Set(&secp256k1BaseY)
	out.Value.Z.SetInt(1)
	return out
}

func (Secp256k1) NewScalar() Scalar {
	return new(Secp256k1Scalar)
}

func (Secp256k1) ScalarBits() int {
	return 256
}

func (Secp256k1) SafeScalarBytes() int {
	return 32
}

func (s Secp256k1) UnmarshalJSON(j []byte) error {
	if err := json.Unmarshal([]byte(`{}`), &s); err != nil {
		return err
	}
	return nil
}

var secp256k1OrderNat, _ = new(safenum.Nat).SetHex("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141")
var secp256k1Order = safenum.ModulusFromNat(secp256k1OrderNat)

func (Secp256k1) Order() *safenum.Modulus {
	return secp256k1Order
}

func (Secp256k1) LiftX(data []byte) (*Secp256k1Point, error) {
	out := new(Secp256k1Point)
	out.Value.Z.SetInt(1)
	if out.Value.X.SetByteSlice(data) {
		return nil, fmt.Errorf("secp256k1Point.UnmarshalBinary: x coordinate out of range")
	}
	if !secp256k1.DecompressY(&out.Value.X, false, &out.Value.Y) {
		return nil, fmt.Errorf("secp256k1Point.UnmarshalBinary: x coordinate not on curve")
	}
	return out, nil
}

func (Secp256k1) Name() string {
	return "secp256k1"
}

type Secp256k1Scalar struct {
	Value secp256k1.ModNScalar
}

func secp256k1CastScalar(generic Scalar) *Secp256k1Scalar {
	out, ok := generic.(*Secp256k1Scalar)
	if !ok {
		panic(fmt.Sprintf("failed to convert to secp256k1Scalar: %v", generic))
	}
	return out
}

func (*Secp256k1Scalar) Curve() Curve {
	return Secp256k1{}
}

func (s *Secp256k1Scalar) MarshalBinary() ([]byte, error) {
	data := s.Value.Bytes()
	return data[:], nil
}

func (s *Secp256k1Scalar) UnmarshalBinary(data []byte) error {
	if len(data) != 32 {
		return fmt.Errorf("invalid length for secp256k1 scalar: %d", len(data))
	}
	var exactData [32]byte
	copy(exactData[:], data)
	if s.Value.SetBytes(&exactData) != 0 {
		return errors.New("invalid bytes for secp256k1 scalar")
	}
	return nil
}

func (s *Secp256k1Scalar) Add(that Scalar) Scalar {
	other := secp256k1CastScalar(that)

	s.Value.Add(&other.Value)
	return s
}

func (s *Secp256k1Scalar) Sub(that Scalar) Scalar {
	other := secp256k1CastScalar(that)

	negated := new(Secp256k1Scalar)
	negated.Value.Set(&other.Value)
	negated.Value.Negate()

	s.Value.Add(&negated.Value)
	return s
}

func (s *Secp256k1Scalar) Mul(that Scalar) Scalar {
	other := secp256k1CastScalar(that)

	s.Value.Mul(&other.Value)
	return s
}

func (s *Secp256k1Scalar) Invert() Scalar {
	s.Value.InverseNonConst()
	return s
}

func (s *Secp256k1Scalar) Negate() Scalar {
	s.Value.Negate()
	return s
}

func (s *Secp256k1Scalar) IsOverHalfOrder() bool {
	return s.Value.IsOverHalfOrder()
}

func (s *Secp256k1Scalar) Equal(that Scalar) bool {
	other := secp256k1CastScalar(that)

	return s.Value.Equals(&other.Value)
}

func (s *Secp256k1Scalar) IsZero() bool {
	return s.Value.IsZero()
}

func (s *Secp256k1Scalar) Set(that Scalar) Scalar {
	other := secp256k1CastScalar(that)

	s.Value.Set(&other.Value)
	return s
}

func (s *Secp256k1Scalar) SetNat(x *safenum.Nat) Scalar {
	reduced := new(safenum.Nat).Mod(x, secp256k1Order)
	s.Value.SetByteSlice(reduced.Bytes())
	return s
}

func (s *Secp256k1Scalar) Act(that Point) Point {
	other := secp256k1CastPoint(that)
	out := new(Secp256k1Point)
	secp256k1.ScalarMultNonConst(&s.Value, &other.Value, &out.Value)
	return out
}

func (s *Secp256k1Scalar) ActOnBase() Point {
	out := new(Secp256k1Point)
	secp256k1.ScalarBaseMultNonConst(&s.Value, &out.Value)
	return out
}

func (s Secp256k1Scalar) MarshalJSON() ([]byte, error) {
	b, e := s.MarshalBinary()
	if e != nil {
		fmt.Println("Failed to Secp256k1Scalar MarshalBinary()", e)
		return nil, e
	}
	return json.Marshal(map[string]interface{}{
		"Value": base64.StdEncoding.EncodeToString(b),
	})
}

// Expects a JSON like "Value": base64
func (s *Secp256k1Scalar) UnmarshalJSON(j []byte) error {
	var tmp map[string]json.RawMessage
	if err := json.Unmarshal(j, &tmp); err != nil {
		fmt.Println("secp256k1scalar unmarshal failed @ tmp:", err)
		return err
	}
	// Strip ""s from json.RawMessage
	randStr := string(tmp["Value"][1 : len(tmp["Value"])-1])
	// Convert base64 to bytes
	randBytes, e := base64.StdEncoding.DecodeString(randStr)
	if e != nil {
		fmt.Println("base64 decoding failed: randBytes", e)
		return e
	}

	var s2 Secp256k1Scalar
	if e := s2.UnmarshalBinary(randBytes); e != nil {
		fmt.Println("secp256k1scalar UnmarshalBinary failed at s: ", e)
		return e
	}
	s.Value = s2.Value
	return nil
}

type Secp256k1Point struct {
	Value secp256k1.JacobianPoint
}

func secp256k1CastPoint(generic Point) *Secp256k1Point {
	out, ok := generic.(*Secp256k1Point)
	if !ok {
		panic(fmt.Sprintf("failed to convert to secp256k1Point: %v", generic))
	}
	return out
}

func (*Secp256k1Point) Curve() Curve {
	return Secp256k1{}
}

func (p *Secp256k1Point) XBytes() []byte {
	p.Value.ToAffine()
	return p.Value.X.Bytes()[:]
}

func (p *Secp256k1Point) YBytes() []byte {
	p.Value.ToAffine()
	return p.Value.Y.Bytes()[:]
}

func (p *Secp256k1Point) MarshalJSON() ([]byte, error) {
	return json.Marshal(map[string]interface{}{
		"X": base64.StdEncoding.EncodeToString(p.Value.X.Bytes()[:]),
		"Y": base64.StdEncoding.EncodeToString(p.Value.Y.Bytes()[:]),
		"Z": base64.StdEncoding.EncodeToString(p.Value.Z.Bytes()[:]),
	})
}

func (p *Secp256k1Point) UnmarshalJSON(j []byte) error {
	var tmp map[string]json.RawMessage
	if err := json.Unmarshal(j, &tmp); err != nil {
		fmt.Println("secp256k1point unmarshal failed @ tmp:", err)
		return err
	}
	base64Xbytes, e := base64.StdEncoding.DecodeString(string(tmp["X"][1 : len(tmp["X"])-1]))
	if e != nil {
		fmt.Println("base64 decode err:", e)
		return e
	}
	base64Ybytes, e := base64.StdEncoding.DecodeString(string(tmp["Y"][1 : len(tmp["Y"])-1]))
	if e != nil {
		fmt.Println("base64 decode err:", e)
		return e
	}
	base64Zbytes, e := base64.StdEncoding.DecodeString(string(tmp["Z"][1 : len(tmp["Z"])-1]))
	if e != nil {
		fmt.Println("base64 decode err:", e)
		return e
	}
	p.Value.X.SetBytes((*[32]byte)(base64Xbytes))
	p.Value.Y.SetBytes((*[32]byte)(base64Ybytes))
	p.Value.Z.SetBytes((*[32]byte)(base64Zbytes))
	return nil
}

func (p *Secp256k1Point) MarshalBinary() ([]byte, error) {
	out := make([]byte, 33)
	// we clone v to not case a race during a hash.Write
	v := p.Value
	v.ToAffine()
	// Doing it this way is compatible with Bitcoin
	out[0] = byte(v.Y.IsOddBit()) + 2
	data := v.X.Bytes()
	copy(out[1:], data[:])
	return out, nil
}

func (p *Secp256k1Point) UnmarshalBinary(data []byte) error {
	if len(data) != 33 {
		return fmt.Errorf("invalid length for secp256k1Point: %d", len(data))
	}
	p.Value.Z.SetInt(1)
	if p.Value.X.SetByteSlice(data[1:]) {
		return fmt.Errorf("secp256k1Point.UnmarshalBinary: x coordinate out of range")
	}
	if !secp256k1.DecompressY(&p.Value.X, data[0] == 3, &p.Value.Y) {
		return fmt.Errorf("secp256k1Point.UnmarshalBinary: x coordinate not on curve")
	}
	return nil
}

func (p *Secp256k1Point) Add(that Point) Point {
	other := secp256k1CastPoint(that)

	out := new(Secp256k1Point)
	secp256k1.AddNonConst(&p.Value, &other.Value, &out.Value)
	return out
}

func (p *Secp256k1Point) Sub(that Point) Point {
	return p.Add(that.Negate())
}

func (p *Secp256k1Point) Set(that Point) Point {
	other := secp256k1CastPoint(that)

	p.Value.Set(&other.Value)
	return p
}

func (p *Secp256k1Point) Negate() Point {
	out := new(Secp256k1Point)
	out.Value.Set(&p.Value)
	out.Value.Y.Negate(1)
	out.Value.Y.Normalize()
	return out
}

func (p *Secp256k1Point) Equal(that Point) bool {
	other := secp256k1CastPoint(that)

	p.Value.ToAffine()
	other.Value.ToAffine()
	return p.Value.X.Equals(&other.Value.X) && p.Value.Y.Equals(&other.Value.Y) && p.Value.Z.Equals(&other.Value.Z)
}

func (p *Secp256k1Point) IsIdentity() bool {
	return p == nil || (p.Value.X.IsZero() && p.Value.Y.IsZero()) || p.Value.Z.IsZero()
}

func (p *Secp256k1Point) HasEvenY() bool {
	p.Value.ToAffine()
	return !p.Value.Y.IsOdd()
}

func (p *Secp256k1Point) XScalar() Scalar {
	out := new(Secp256k1Scalar)
	p.Value.ToAffine()
	out.Value.SetBytes(p.Value.X.Bytes())
	return out
}

func PrintAffine(p *Secp256k1Point) {
	v := p.Value
	v.ToAffine()
	fmt.Printf("Affined secp256k1point: %+v %+v %+v\n", v.X, v.Y, v.Z)
	return
}
