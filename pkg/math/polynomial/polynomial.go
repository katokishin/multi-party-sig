package polynomial

import (
	"crypto/rand"
	"encoding/json"
	"fmt"

	"github.com/taurusgroup/multi-party-sig/pkg/math/curve"
	"github.com/taurusgroup/multi-party-sig/pkg/math/sample"
)

// Polynomial represents f(X) = a₀ + a₁⋅X + … + aₜ⋅Xᵗ.
type Polynomial struct {
	Group        curve.Curve
	Coefficients []curve.Scalar
}

// NewPolynomial generates a Polynomial f(X) = secret + a₁⋅X + … + aₜ⋅Xᵗ,
// with coefficients in ℤₚ, and degree t.
func NewPolynomial(group curve.Curve, degree int, constant curve.Scalar) *Polynomial {
	polynomial := &Polynomial{
		Group:        group,
		Coefficients: make([]curve.Scalar, degree+1),
	}

	// if the constant is nil, we interpret it as 0.
	if constant == nil {
		constant = group.NewScalar()
	}
	polynomial.Coefficients[0] = constant

	for i := 1; i <= degree; i++ {
		polynomial.Coefficients[i] = sample.Scalar(rand.Reader, group)
	}

	return polynomial
}

// Evaluate evaluates a polynomial in a given variable index
// We use Horner's method: https://en.wikipedia.org/wiki/Horner%27s_method
func (p *Polynomial) Evaluate(index curve.Scalar) curve.Scalar {
	if index.IsZero() {
		panic("attempt to leak secret")
	}

	result := p.Group.NewScalar()
	// reverse order
	for i := len(p.Coefficients) - 1; i >= 0; i-- {
		// bₙ₋₁ = bₙ * x + aₙ₋₁
		result.Mul(index).Add(p.Coefficients[i])
	}
	return result
}

// Constant returns a reference to the constant coefficient of the polynomial.
func (p *Polynomial) Constant() curve.Scalar {
	return p.Group.NewScalar().Set(p.Coefficients[0])
}

// Degree is the highest power of the Polynomial.
func (p *Polynomial) Degree() uint32 {
	return uint32(len(p.Coefficients)) - 1
}

func (p Polynomial) MarshalJSON() ([]byte, error) {
	return json.Marshal(map[string]interface{}{
		"Group":        p.Group,
		"Coefficients": p.Coefficients,
	})
}

func (p *Polynomial) UnmarshalJSON(j []byte) error {
	var tmp map[string]json.RawMessage
	if err := json.Unmarshal(j, &tmp); err != nil {
		fmt.Println("polynomial unmarshal failed @ tmp:", err)
		return err
	}

	var cs []curve.Secp256k1Scalar
	if err := json.Unmarshal(tmp["Coefficients"], &cs); err != nil {
		fmt.Println("Polynomial unmarshal failed @ coefficients:", err)
		return err
	}
	scalars := make([]curve.Scalar, len(cs))
	for i, _ := range cs {
		scalars[i] = &cs[i]
	}

	p.Group = curve.Secp256k1{}
	p.Coefficients = scalars
	return nil
}
