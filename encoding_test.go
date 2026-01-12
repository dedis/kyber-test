package kyber_test

import (
	"testing"

	"github.com/stretchr/testify/require"
	kyberv3 "go.dedis.ch/kyber/v3"
	suitesv3 "go.dedis.ch/kyber/v3/suites"
	suitesv4 "go.dedis.ch/kyber/v4/suites"
	"go.dedis.ch/protobuf"

	v3ed "go.dedis.ch/kyber/v3/group/edwards25519"
	v3share "go.dedis.ch/kyber/v3/share"
	v4share "go.dedis.ch/kyber/v4/share"
)

func TestEncodingDecodingV3(t *testing.T) {
	type priShareV3Wrapper struct {
		share v3share.PriShare
	}

	type priShareV4Wrapper struct {
		share v4share.PriShare
	}

	// create a PriShare
	n := 10
	threshold := n/2 + 1

	g3 := v3ed.NewBlakeSHA256Ed25519()

	r3 := g3.RandomStream()
	s3 := g3.Scalar().Pick(r3)

	p3 := v3share.NewPriPoly(g3, threshold, s3, r3)
	shares := p3.Shares(n)

	sharev3 := shares[0]

	sharev3.I = -1

	// encode the V3 PriShare
	sharev3Encoded, err := protobuf.Encode(sharev3)
	require.NoError(t, err)

	// verify that v3 can decode the previousely encoded PriShare
	var reSharev3 priShareV3Wrapper
	err = protobuf.Decode(sharev3Encoded, &reSharev3)
	require.NoError(t, err)

	// compare the V3 and V4 PriShare are equal
	require.Equal(t, *sharev3, reSharev3.share)

	// decode the previousely encoded PriShare in a V4
	var sharev4 priShareV4Wrapper
	err = protobuf.Decode(sharev3Encoded, &sharev4)
	require.NoError(t, err)

	// compare the V3 and V4 PriShare are equal
	require.Equal(t, reSharev3.share, sharev4.share)
}

func TestEncodingPoint(t *testing.T) {
	// Initialize a Point struct using kyber
	type PointsV3 struct {
		P1 kyberv3.Point
		P2 kyberv3.Point
	}

	bn256v3 := suitesv3.MustFind("bn256.adapter")
	ed25519v3 := suitesv3.MustFind("ed25519")

	protobuf.RegisterInterface(func() interface{} { return bn256v3.Point() })
	protobuf.RegisterInterface(func() interface{} { return ed25519v3.Point() })

	ppv3 := PointsV3{
		P1: bn256v3.Point(),
		P2: ed25519v3.Point(),
	}

	buf, err := protobuf.Encode(&ppv3)
	require.NoError(t, err)

	var dppv3 PointsV3
	err = protobuf.Decode(buf, &dppv3)
	require.NoError(t, err)
	require.Equal(t, ppv3.P1.String(), dppv3.P1.String())
	require.Equal(t, ppv3.P2.String(), dppv3.P2.String())

	type PointsV4 struct {
		P1 kyberv3.Point
		P2 kyberv3.Point
	}

	bn256v4 := suitesv4.MustFind("bn256.adapter")
	ed25519v4 := suitesv4.MustFind("ed25519")

	protobuf.RegisterInterface(func() interface{} { return bn256v4.Point() })
	protobuf.RegisterInterface(func() interface{} { return ed25519v4.Point() })

	var dppv4 PointsV4
	err = protobuf.Decode(buf, &dppv4)
	require.NoError(t, err)
	require.Equal(t, ppv3.P1.String(), dppv4.P1.String())
	require.Equal(t, ppv3.P2.String(), dppv4.P2.String())
}

func TestEncodingScalar(t *testing.T) {
	// Initialize a Scalar sstruct using kyber

}
