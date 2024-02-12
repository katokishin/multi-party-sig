package polynomial

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"

	"github.com/cronokirby/saferith"
	"github.com/fxamacker/cbor/v2"
	"github.com/taurusgroup/multi-party-sig/pkg/math/curve"
)

type rawExponentData struct {
	IsConstant   bool
	Coefficients []curve.Point
}

// Exponent represent a polynomial F(X) whose Coefficients belong to a Group 𝔾.
type Exponent struct {
	Group curve.Curve
	// IsConstant indicates that the constant coefficient is the identity.
	// We do this so that we never need to send an encoded Identity point, and thus consider it invalid
	IsConstant bool
	// Coefficients is a list of curve.Point representing the Coefficients of a polynomial over an elliptic curve.
	Coefficients []curve.Point
}

// NewPolynomialExponent generates an Exponent polynomial F(X) = [secret + a₁•X + … + aₜ•Xᵗ]•G,
// with Coefficients in 𝔾, and degree t.
func NewPolynomialExponent(polynomial *Polynomial) *Exponent {
	p := &Exponent{
		Group:        polynomial.Group,
		IsConstant:   polynomial.Coefficients[0].IsZero(),
		Coefficients: make([]curve.Point, 0, len(polynomial.Coefficients)),
	}

	for i, c := range polynomial.Coefficients {
		if p.IsConstant && i == 0 {
			continue
		}
		p.Coefficients = append(p.Coefficients, c.ActOnBase())
	}

	return p
}

// Evaluate returns F(x) = [secret + a₁•x + … + aₜ•xᵗ]•G.
func (p *Exponent) Evaluate(x curve.Scalar) curve.Point {
	result := p.Group.NewPoint()

	for i := len(p.Coefficients) - 1; i >= 0; i-- {
		// Bₙ₋₁ = [x]Bₙ  + Aₙ₋₁
		result = x.Act(result).Add(p.Coefficients[i])
	}

	if p.IsConstant {
		// result is B₁
		// we want B₀ = [x]B₁ + A₀ = [x]B₁
		result = x.Act(result)
	}

	return result
}

// evaluateClassic evaluates a polynomial in a given variable index
// We do the classic method, where we compute all powers of x.
func (p *Exponent) evaluateClassic(x curve.Scalar) curve.Point {
	var tmp curve.Point

	xPower := p.Group.NewScalar().SetNat(new(saferith.Nat).SetUint64(1))
	result := p.Group.NewPoint()

	if p.IsConstant {
		// since we start at index 1 of the polynomial, x must be x and not 1
		xPower.Mul(x)
	}

	for i := 0; i < len(p.Coefficients); i++ {
		// tmp = [xⁱ]Aᵢ
		tmp = xPower.Act(p.Coefficients[i])
		// result += [xⁱ]Aᵢ
		result = result.Add(tmp)
		// x = xⁱ⁺¹
		xPower.Mul(x)
	}
	return result
}

// Degree returns the degree t of the polynomial.
func (p *Exponent) Degree() int {
	if p.IsConstant {
		return len(p.Coefficients)
	}
	return len(p.Coefficients) - 1
}

func (p *Exponent) add(q *Exponent) error {
	if len(p.Coefficients) != len(q.Coefficients) {
		return errors.New("q is not the same length as p")
	}

	if p.IsConstant != q.IsConstant {
		return errors.New("p and q differ in 'IsConstant'")
	}

	for i := 0; i < len(p.Coefficients); i++ {
		p.Coefficients[i] = p.Coefficients[i].Add(q.Coefficients[i])
	}

	return nil
}

// Sum creates a new Polynomial in the Exponent, by summing a slice of existing ones.
func Sum(polynomials []*Exponent) (*Exponent, error) {
	var err error

	// Create the new polynomial by copying the first one given
	summed := polynomials[0].copy()

	// we assume all polynomials have the same degree as the first
	for j := 1; j < len(polynomials); j++ {
		err = summed.add(polynomials[j])
		if err != nil {
			return nil, err
		}
	}
	return summed, nil
}

func (p *Exponent) copy() *Exponent {
	q := &Exponent{
		Group:        p.Group,
		IsConstant:   p.IsConstant,
		Coefficients: make([]curve.Point, 0, len(p.Coefficients)),
	}
	for i := 0; i < len(p.Coefficients); i++ {
		q.Coefficients = append(q.Coefficients, p.Coefficients[i])
	}
	return q
}

// Equal returns true if p ≡ other.
func (p *Exponent) Equal(other Exponent) bool {
	if p.IsConstant != other.IsConstant {
		return false
	}
	if len(p.Coefficients) != len(other.Coefficients) {
		return false
	}
	for i := 0; i < len(p.Coefficients); i++ {
		if !p.Coefficients[i].Equal(other.Coefficients[i]) {
			return false
		}
	}
	return true
}

// Constant returns the constant coefficient of the polynomial 'in the exponent'.
func (p *Exponent) Constant() curve.Point {
	c := p.Group.NewPoint()
	if p.IsConstant {
		return c
	}
	return p.Coefficients[0]
}

// WriteTo implements io.WriterTo and should be used within the hash.Hash function.
func (p *Exponent) WriteTo(w io.Writer) (int64, error) {
	data, err := p.MarshalBinary()
	if err != nil {
		return 0, err
	}
	total, err := w.Write(data)
	return int64(total), err
}

// Domain implements hash.WriterToWithDomain, and separates this type within hash.Hash.
func (*Exponent) Domain() string {
	return "Exponent"
}

func EmptyExponent(Group curve.Curve) *Exponent {
	// TODO create custom marshaller
	return &Exponent{Group: Group}
}

func (e *Exponent) UnmarshalBinary(data []byte) error {
	if e == nil || e.Group == nil {
		return errors.New("can't unmarshal Exponent with no Group")
	}
	Group := e.Group
	size := binary.BigEndian.Uint32(data)
	e.Coefficients = make([]curve.Point, int(size))
	for i := 0; i < len(e.Coefficients); i++ {
		e.Coefficients[i] = Group.NewPoint()
	}
	rawExponent := rawExponentData{Coefficients: e.Coefficients}
	if err := cbor.Unmarshal(data[4:], &rawExponent); err != nil {
		return err
	}
	e.Group = Group
	e.Coefficients = rawExponent.Coefficients
	e.IsConstant = rawExponent.IsConstant
	return nil
}

func (e *Exponent) MarshalBinary() ([]byte, error) {
	data, err := cbor.Marshal(rawExponentData{
		IsConstant:   e.IsConstant,
		Coefficients: e.Coefficients,
	})
	if err != nil {
		return nil, err
	}
	out := make([]byte, 4+len(data))
	size := len(e.Coefficients)
	binary.BigEndian.PutUint32(out, uint32(size))
	copy(out[4:], data)
	return out, nil
}

func (e Exponent) MarshalJSON() ([]byte, error) {
	return json.Marshal(map[string]interface{}{
		"Group":        "{}",
		"IsConstant":   e.IsConstant,
		"Coefficients": e.Coefficients,
	})
}

func (e *Exponent) UnmarshalJSON(j []byte) error {
	var tmp map[string]json.RawMessage
	if err := json.Unmarshal(j, &tmp); err != nil {
		fmt.Println("Exponent unmarshal failed @ tmp:", err)
		return err
	}

	var isConstant bool
	if err := json.Unmarshal(tmp["IsConstant"], &isConstant); err != nil {
		fmt.Println("Exponent unmarshal failed @ isConstant:", err)
		return err
	}

	var coefficients []curve.Secp256k1Point
	if err := json.Unmarshal(tmp["Coefficients"], &coefficients); err != nil {
		fmt.Println("Exponent unmarshal failed @ coefficients:", err)
		return err
	}
	coes := make([]curve.Point, len(coefficients))
	for i, _ := range coefficients {
		coes[i] = &coefficients[i]
	}

	e.Group = curve.Secp256k1{}
	e.Coefficients = coes
	e.IsConstant = isConstant
	return nil
}

func (e *Exponent) AffineIt() *Exponent {
	for i, co := range e.Coefficients {
		co := co
		co.(*curve.Secp256k1Point).Value.ToAffine()
		e.Coefficients[i] = co
	}
	return e
}
