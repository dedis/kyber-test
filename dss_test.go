package kyber_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	kyberv3 "go.dedis.ch/kyber/v3"
	edv3 "go.dedis.ch/kyber/v3/group/edwards25519"
	dkgv3 "go.dedis.ch/kyber/v3/share/dkg/rabin"
	dssv3 "go.dedis.ch/kyber/v3/sign/dss"
	kyberv4 "go.dedis.ch/kyber/v4"
	edv4 "go.dedis.ch/kyber/v4/group/edwards25519"
	dkgv4 "go.dedis.ch/kyber/v4/share/dkg/rabin"
	dssv4 "go.dedis.ch/kyber/v4/sign/dss"
)

const nbParticipants = uint32(7)
const threshold = nbParticipants/2 + 1

var messageToSign = []byte("NK@XG88ZIHA@NMRFLRECY#RVTCIU#8VJ5")

var suiteV3 = edv3.NewBlakeSHA256Ed25519()
var partPubsV3 []kyberv3.Point
var partSecV3 []kyberv3.Scalar
var longtermsV3 []*dkgv3.DistKeyShare
var randomsV3 []*dkgv3.DistKeyShare

var suiteV4 = edv4.NewBlakeSHA256Ed25519()
var partPubsV4 []kyberv4.Point
var partSecV4 []kyberv4.Scalar
var longtermsV4 []*dkgv4.DistKeyShare
var randomsV4 []*dkgv4.DistKeyShare

func init() {
	partPubsV3 = make([]kyberv3.Point, nbParticipants)
	partSecV3 = make([]kyberv3.Scalar, nbParticipants)
	for i := uint32(0); i < nbParticipants; i++ {
		sec, pub := genPairV3()
		partPubsV3[i] = pub
		partSecV3[i] = sec
	}
	longtermsV3 = genDistSecretV3()
	randomsV3 = genDistSecretV3()

	partPubsV4 = make([]kyberv4.Point, nbParticipants)
	partSecV4 = make([]kyberv4.Scalar, nbParticipants)
	for i := uint32(0); i < nbParticipants; i++ {
		sec, pub := genPairV4()
		partPubsV4[i] = pub
		partSecV4[i] = sec
	}
	longtermsV4 = genDistSecretV4()
	randomsV4 = genDistSecretV4()
}

// TestCrossVersionDSSCompatibility tests that DSS serialized by v3 can be
// verified by v4 and vice versa.
func TestCrossVersionDSSCompatibility(t *testing.T) {
	dsssV3 := make([]*dssv3.DSS, nbParticipants)
	pssV3 := make([]*dssv3.PartialSig, nbParticipants)
	for i := uint32(0); i < nbParticipants; i++ {
		dsssV3[i] = getDSSV3(i)
		ps, err := dsssV3[i].PartialSig()
		require.Nil(t, err)
		require.NotNil(t, ps)
		pssV3[i] = ps
	}
	for i, dss := range dsssV3 {
		for j, ps := range pssV3 {
			if i == j {
				continue
			}
			require.Nil(t, dss.ProcessPartialSig(ps))
		}
	}
	// issue and verify signature
	dss0V3 := dsssV3[0]
	signatureV3, err := dss0V3.Signature()
	assert.NotNil(t, signatureV3)
	assert.Nil(t, err)

	dsssV4 := make([]*dssv4.DSS, nbParticipants)
	pss := make([]*dssv4.PartialSig, nbParticipants)
	for i := uint32(0); i < nbParticipants; i++ {
		dsssV4[i] = getDSSV4(i)
		ps, err := dsssV4[i].PartialSig()
		require.Nil(t, err)
		require.NotNil(t, ps)
		pss[i] = ps
	}
	for i, dss := range dsssV4 {
		for j, ps := range pss {
			if i == j {
				continue
			}
			require.Nil(t, dss.ProcessPartialSig(ps))
		}
	}
	// issue and verify signature
	dss0V4 := dsssV4[0]
	signatureV4, err := dss0V4.Signature()
	assert.NotNil(t, signatureV4)
	assert.Nil(t, err)

	// TODO: verify V3 signature with V4

	// TODO: verify V4 signature with V3



	// the following shows kyber.point are not compatible between v3 and v4

	//// verify v4 signature with v3 eddsa
	//pubPointV3 := longtermsV3[0].Public().(kyberv3.Point)
	//err = eddsav3.Verify(pubPointV3, messageToSign, signatureV4)
	//assert.Nil(t, err)
	//
	//// verify v3 signature with v4 eddsa
	//pubPointV4 := longtermsV4[0].Public().(kyberv4.Point)
	//err = eddsav4.Verify(pubPointV4, messageToSign, signatureV3)
	//assert.Nil(t, err)
}

func getDSSV3(i uint32) *dssv3.DSS {
	dss, err := dssv3.NewDSS(
		suiteV3,
		partSecV3[i],
		partPubsV3,
		longtermsV3[i],
		randomsV3[i],
		messageToSign,
		int(threshold))
	if dss == nil || err != nil {
		panic("nil dss")
	}
	return dss
}

func getDSSV4(i uint32) *dssv4.DSS {
	dss, err := dssv4.NewDSS(
		suiteV4,
		partSecV4[i],
		partPubsV4,
		longtermsV4[i],
		randomsV4[i],
		messageToSign,
		threshold)
	if dss == nil || err != nil {
		panic("nil dss")
	}
	return dss
}

func genDistSecretV3() []*dkgv3.DistKeyShare {
	dkgs := make([]*dkgv3.DistKeyGenerator, nbParticipants)
	for i := uint32(0); i < nbParticipants; i++ {
		dkg, err := dkgv3.NewDistKeyGenerator(suiteV3, partSecV3[i], partPubsV3, int(threshold))
		if err != nil {
			panic(err)
		}
		dkgs[i] = dkg
	}
	// full secret sharing exchange
	// 1. broadcast deals
	resps := make([]*dkgv3.Response, 0, nbParticipants*nbParticipants)
	for _, dk := range dkgs {
		deals, err := dk.Deals()
		if err != nil {
			panic(err)
		}
		for i, deal := range deals {
			resp, err := dkgs[i].ProcessDeal(deal)
			if err != nil {
				panic(err)
			}
			if !resp.Response.Approved {
				panic("wrong approval")
			}
			resps = append(resps, resp)
		}
	}
	// 2. Broadcast responses
	for _, resp := range resps {
		for h, dk := range dkgs {
			// ignore all messages from ourself
			if resp.Response.Index == uint32(h) {
				continue
			}
			j, err := dk.ProcessResponse(resp)
			if err != nil || j != nil {
				panic("wrongProcessResponse")
			}
		}
	}
	// 4. Broadcast secret commitment
	for i, d := range dkgs {
		scs, err := d.SecretCommits()
		if err != nil {
			panic("wrong SecretCommits")
		}
		for j, d2 := range dkgs {
			if i == j {
				continue
			}
			cc, err := d2.ProcessSecretCommits(scs)
			if err != nil || cc != nil {
				panic("wrong ProcessSecretCommits")
			}
		}
	}

	// 5. reveal shares
	dkss := make([]*dkgv3.DistKeyShare, len(dkgs))
	for i, dkg := range dkgs {
		dks, err := dkg.DistKeyShare()
		if err != nil {
			panic(err)
		}
		dkss[i] = dks
	}
	return dkss

}

func genDistSecretV4() []*dkgv4.DistKeyShare {
	dkgs := make([]*dkgv4.DistKeyGenerator, nbParticipants)
	for i := uint32(0); i < nbParticipants; i++ {
		dk, err := dkgv4.NewDistKeyGenerator(suiteV4, partSecV4[i], partPubsV4, threshold)
		if err != nil {
			panic(err)
		}
		dkgs[i] = dk
	}
	// full secret sharing exchange
	// 1. broadcast deals
	resps := make([]*dkgv4.Response, 0, nbParticipants*nbParticipants)
	for _, dkg := range dkgs {
		deals, err := dkg.Deals()
		if err != nil {
			panic(err)
		}
		for i, d := range deals {
			resp, err := dkgs[i].ProcessDeal(d)
			if err != nil {
				panic(err)
			}
			if !resp.Response.Approved {
				panic("wrong approval")
			}
			resps = append(resps, resp)
		}
	}
	// 2. Broadcast responses
	for _, resp := range resps {
		for h, d := range dkgs {
			// ignore all messages from ourself
			if resp.Response.Index == uint32(h) {
				continue
			}
			j, err := d.ProcessResponse(resp)
			if err != nil || j != nil {
				panic("wrongProcessResponse")
			}
		}
	}
	// 4. Broadcast secret commitment
	for i, dk1 := range dkgs {
		scs, err := dk1.SecretCommits()
		if err != nil {
			panic("wrong SecretCommits")
		}
		for j, dk2 := range dkgs {
			if i == j {
				continue
			}
			cc, err := dk2.ProcessSecretCommits(scs)
			if err != nil || cc != nil {
				panic("wrong ProcessSecretCommits")
			}
		}
	}

	// 5. reveal shares
	dkss := make([]*dkgv4.DistKeyShare, len(dkgs))
	for i, dk := range dkgs {
		dks, err := dk.DistKeyShare()
		if err != nil {
			panic(err)
		}
		dkss[i] = dks
	}
	return dkss

}

func genPairV3() (kyberv3.Scalar, kyberv3.Point) {
	sc := suiteV3.Scalar().Pick(suiteV3.RandomStream())
	return sc, suiteV3.Point().Mul(sc, nil)
}

func genPairV4() (kyberv4.Scalar, kyberv4.Point) {
	sc := suiteV4.Scalar().Pick(suiteV4.RandomStream())
	return sc, suiteV4.Point().Mul(sc, nil)
}
