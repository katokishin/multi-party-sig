package zkdec

import (
	"crypto/rand"
	"testing"

	"github.com/fxamacker/cbor/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/taurusgroup/multi-party-sig/internal/hash"
	"github.com/taurusgroup/multi-party-sig/pkg/math/curve"
	"github.com/taurusgroup/multi-party-sig/pkg/math/sample"
	"github.com/taurusgroup/multi-party-sig/pkg/zk"
)

func TestDec(t *testing.T) {
	var group curve.Curve
	verifierPedersen := zk.Pedersen
	prover := zk.ProverPaillierPublic

	y := sample.IntervalL(rand.Reader)
	x := group.NewScalar().SetInt(y)

	C, rho := prover.Enc(y)

	public := Public{
		C:      C,
		X:      x,
		Prover: prover,
		Aux:    verifierPedersen,
	}
	private := Private{
		Y:   y,
		Rho: rho,
	}

	proof := NewProof(group, hash.New(), public, private)
	assert.True(t, proof.Verify(group, hash.New(), public))

	out, err := cbor.Marshal(proof)
	require.NoError(t, err, "failed to marshal proof")
	proof2 := &Proof{}
	require.NoError(t, cbor.Unmarshal(out, proof2), "failed to unmarshal proof")
	out2, err := cbor.Marshal(proof2)
	require.NoError(t, err, "failed to marshal 2nd proof")
	proof3 := &Proof{}
	require.NoError(t, cbor.Unmarshal(out2, proof3), "failed to unmarshal 2nd proof")

	assert.True(t, proof3.Verify(group, hash.New(), public))
}
