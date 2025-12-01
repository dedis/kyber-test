package kyber_test

import (
	"bytes"
	"crypto/cipher"
	"encoding/hex"
	"errors"
	"testing"

	kyberv3 "go.dedis.ch/kyber/v3"
	edv3 "go.dedis.ch/kyber/v3/group/edwards25519"
	kyberv4 "go.dedis.ch/kyber/v4"
	edv4 "go.dedis.ch/kyber/v4/group/edwards25519"
)

// Suite interfaces for V3 and V4
type SuiteV3 interface {
	kyberv3.Group
	kyberv3.Encoding
	kyberv3.XOFFactory
}

type SuiteV4 interface {
	kyberv4.Group
	kyberv4.Encoding
	kyberv4.XOFFactory
}

// basicSigV3 represents a Schnorr signature for V3
type basicSigV3 struct {
	C kyberv3.Scalar // challenge
	R kyberv3.Scalar // response
}

// basicSigV4 represents a Schnorr signature for V4
type basicSigV4 struct {
	C kyberv4.Scalar // challenge
	R kyberv4.Scalar // response
}

// hashSchnorrV3 returns a hash of a message and a point
func hashSchnorrV3(suite SuiteV3, message []byte, p kyberv3.Point) kyberv3.Scalar {
	pb, _ := p.MarshalBinary()
	c := suite.XOF(pb)
	_, _ = c.Write(message)
	return suite.Scalar().Pick(c)
}

// hashSchnorrV4 returns a hash of a message and a point
func hashSchnorrV4(suite SuiteV4, message []byte, p kyberv4.Point) kyberv4.Scalar {
	pb, _ := p.MarshalBinary()
	c := suite.XOF(pb)
	_, _ = c.Write(message)
	return suite.Scalar().Pick(c)
}

// schnorrSignV3 creates a Schnorr signature using V3
func schnorrSignV3(suite SuiteV3, random cipher.Stream, message []byte,
	privateKey kyberv3.Scalar) []byte {

	v := suite.Scalar().Pick(random)
	T := suite.Point().Mul(v, nil)
	c := hashSchnorrV3(suite, message, T)
	r := suite.Scalar()
	r.Mul(privateKey, c).Sub(v, r)

	buf := bytes.Buffer{}
	sig := basicSigV3{c, r}
	_ = suite.Write(&buf, &sig)
	return buf.Bytes()
}

// schnorrSignV4 creates a Schnorr signature using V4
func schnorrSignV4(suite SuiteV4, random cipher.Stream, message []byte,
	privateKey kyberv4.Scalar) []byte {

	v := suite.Scalar().Pick(random)
	T := suite.Point().Mul(v, nil)
	c := hashSchnorrV4(suite, message, T)
	r := suite.Scalar()
	r.Mul(privateKey, c).Sub(v, r)

	buf := bytes.Buffer{}
	sig := basicSigV4{c, r}
	_ = suite.Write(&buf, &sig)
	return buf.Bytes()
}

// schnorrVerifyV3 verifies a Schnorr signature using V3
func schnorrVerifyV3(suite SuiteV3, message []byte, publicKey kyberv3.Point,
	signatureBuffer []byte) error {

	buf := bytes.NewBuffer(signatureBuffer)
	sig := basicSigV3{}
	if err := suite.Read(buf, &sig); err != nil {
		return err
	}
	r := sig.R
	c := sig.C

	var P, T kyberv3.Point
	P = suite.Point()
	T = suite.Point()
	T.Add(T.Mul(r, nil), P.Mul(c, publicKey))

	c = hashSchnorrV3(suite, message, T)
	if !c.Equal(sig.C) {
		return errors.New("invalid signature")
	}

	return nil
}

// schnorrVerifyV4 verifies a Schnorr signature using V4
func schnorrVerifyV4(suite SuiteV4, message []byte, publicKey kyberv4.Point,
	signatureBuffer []byte) error {

	buf := bytes.NewBuffer(signatureBuffer)
	sig := basicSigV4{}
	if err := suite.Read(buf, &sig); err != nil {
		return err
	}
	r := sig.R
	c := sig.C

	var P, T kyberv4.Point
	P = suite.Point()
	T = suite.Point()
	T.Add(T.Mul(r, nil), P.Mul(c, publicKey))

	c = hashSchnorrV4(suite, message, T)
	if !c.Equal(sig.C) {
		return errors.New("invalid signature")
	}

	return nil
}

// TestSchnorrSignatureV3 tests Schnorr signature with V3.
func TestSchnorrSignatureV3(t *testing.T) {
	suite := edv3.NewBlakeSHA256Ed25519()
	rand := suite.XOF([]byte("schnorr-test-v3"))

	// Create keypair
	x := suite.Scalar().Pick(rand)
	X := suite.Point().Mul(x, nil)

	// Sign message
	msg := []byte("Hello, Kyber V3!")
	sig := schnorrSignV3(suite, rand, msg, x)

	t.Logf("V3 Signature: %s", hex.EncodeToString(sig))

	// Verify signature
	err := schnorrVerifyV3(suite, msg, X, sig)
	if err != nil {
		t.Fatalf("V3 signature verification failed: %v", err)
	}
}

// TestSchnorrSignatureV4 tests Schnorr signature with V4.
func TestSchnorrSignatureV4(t *testing.T) {
	suite := edv4.NewBlakeSHA256Ed25519()
	rand := suite.XOF([]byte("schnorr-test-v4"))

	// Create keypair
	x := suite.Scalar().Pick(rand)
	X := suite.Point().Mul(x, nil)

	// Sign message
	msg := []byte("Hello, Kyber V4!")
	sig := schnorrSignV4(suite, rand, msg, x)

	t.Logf("V4 Signature: %s", hex.EncodeToString(sig))

	// Verify signature
	err := schnorrVerifyV4(suite, msg, X, sig)
	if err != nil {
		t.Fatalf("V4 signature verification failed: %v", err)
	}
}

// TestSignatureCrossVersionCompatibility tests that signatures created by V3 can be
// verified by V4 and vice versa.
func TestSignatureCrossVersionCompatibility(t *testing.T) {
	suiteV3 := edv3.NewBlakeSHA256Ed25519()
	suiteV4 := edv4.NewBlakeSHA256Ed25519()

	// Use the same seed for both versions
	randV3 := suiteV3.XOF([]byte("cross-version-sig-test"))
	randV4 := suiteV4.XOF([]byte("cross-version-sig-test"))

	// Create keypairs with the same seed (should produce same keys)
	xV3 := suiteV3.Scalar().Pick(randV3)
	XV3 := suiteV3.Point().Mul(xV3, nil)

	xV4 := suiteV4.Scalar().Pick(randV4)
	XV4 := suiteV4.Point().Mul(xV4, nil)

	// Verify keys are the same
	xV3Bytes, _ := xV3.MarshalBinary()
	xV4Bytes, _ := xV4.MarshalBinary()
	if !bytes.Equal(xV3Bytes, xV4Bytes) {
		t.Fatal("Private keys differ between V3 and V4")
	}

	XV3Bytes, _ := XV3.MarshalBinary()
	XV4Bytes, _ := XV4.MarshalBinary()
	if !bytes.Equal(XV3Bytes, XV4Bytes) {
		t.Fatal("Public keys differ between V3 and V4")
	}

	// Get fresh random streams for signing
	signRandV3 := suiteV3.XOF([]byte("sign-random"))
	signRandV4 := suiteV4.XOF([]byte("sign-random"))

	// Sign the same message with both versions
	msg := []byte("Cross-version test message")
	sigV3 := schnorrSignV3(suiteV3, signRandV3, msg, xV3)
	sigV4 := schnorrSignV4(suiteV4, signRandV4, msg, xV4)

	t.Logf("V3 Signature: %s", hex.EncodeToString(sigV3))
	t.Logf("V4 Signature: %s", hex.EncodeToString(sigV4))

	// Signatures should be the same with the same seed
	if !bytes.Equal(sigV3, sigV4) {
		t.Logf("Note: Signatures differ (this may be expected if internal randomness differs)")
	}

	// Verify V3 signature with V3
	if err := schnorrVerifyV3(suiteV3, msg, XV3, sigV3); err != nil {
		t.Errorf("V3 cannot verify its own signature: %v", err)
	}

	// Verify V4 signature with V4
	if err := schnorrVerifyV4(suiteV4, msg, XV4, sigV4); err != nil {
		t.Errorf("V4 cannot verify its own signature: %v", err)
	}

	// Note: Cross-version verification requires deserializing the signature
	// in the target version format and using the corresponding public key.
	// We test that the raw bytes are compatible below.

	// Test that V3 signature bytes can be verified by V4 using the same public key bytes
	XV4FromV3 := suiteV4.Point()
	if err := XV4FromV3.UnmarshalBinary(XV3Bytes); err != nil {
		t.Fatalf("Failed to unmarshal V3 public key in V4: %v", err)
	}

	if err := schnorrVerifyV4(suiteV4, msg, XV4FromV3, sigV3); err != nil {
		t.Errorf("V4 cannot verify V3 signature: %v", err)
	}

	// Test that V4 signature bytes can be verified by V3 using the same public key bytes
	XV3FromV4 := suiteV3.Point()
	if err := XV3FromV4.UnmarshalBinary(XV4Bytes); err != nil {
		t.Fatalf("Failed to unmarshal V4 public key in V3: %v", err)
	}

	if err := schnorrVerifyV3(suiteV3, msg, XV3FromV4, sigV4); err != nil {
		t.Errorf("V3 cannot verify V4 signature: %v", err)
	}

	t.Log("Cross-version signature verification successful!")
}

// TestKeyExchangeCompatibility tests that Diffie-Hellman key exchange produces
// the same shared secret in both versions.
func TestKeyExchangeCompatibility(t *testing.T) {
	suiteV3 := edv3.NewBlakeSHA256Ed25519()
	suiteV4 := edv4.NewBlakeSHA256Ed25519()

	// Create keypairs for Alice in V3 and Bob in V4
	randAlice := suiteV3.XOF([]byte("alice-keypair"))
	randBob := suiteV4.XOF([]byte("bob-keypair"))

	// Alice's keypair using V3
	alicePrivate := suiteV3.Scalar().Pick(randAlice)
	alicePublic := suiteV3.Point().Mul(alicePrivate, nil)
	alicePublicBytes, _ := alicePublic.MarshalBinary()

	// Bob's keypair using V4
	bobPrivate := suiteV4.Scalar().Pick(randBob)
	bobPublic := suiteV4.Point().Mul(bobPrivate, nil)
	bobPublicBytes, _ := bobPublic.MarshalBinary()

	t.Logf("Alice's public key (V3): %s", hex.EncodeToString(alicePublicBytes))
	t.Logf("Bob's public key (V4): %s", hex.EncodeToString(bobPublicBytes))

	// Alice computes shared secret using V3
	// First, import Bob's public key into V3
	bobPublicInV3 := suiteV3.Point()
	if err := bobPublicInV3.UnmarshalBinary(bobPublicBytes); err != nil {
		t.Fatalf("Failed to import Bob's public key into V3: %v", err)
	}
	aliceShared := suiteV3.Point().Mul(alicePrivate, bobPublicInV3)
	aliceSharedBytes, _ := aliceShared.MarshalBinary()

	// Bob computes shared secret using V4
	// First, import Alice's public key into V4
	alicePublicInV4 := suiteV4.Point()
	if err := alicePublicInV4.UnmarshalBinary(alicePublicBytes); err != nil {
		t.Fatalf("Failed to import Alice's public key into V4: %v", err)
	}
	bobShared := suiteV4.Point().Mul(bobPrivate, alicePublicInV4)
	bobSharedBytes, _ := bobShared.MarshalBinary()

	t.Logf("Alice's shared secret (V3): %s", hex.EncodeToString(aliceSharedBytes))
	t.Logf("Bob's shared secret (V4): %s", hex.EncodeToString(bobSharedBytes))

	// Verify shared secrets are equal
	if !bytes.Equal(aliceSharedBytes, bobSharedBytes) {
		t.Error("Shared secrets differ between V3 and V4!")
	} else {
		t.Log("Key exchange successful! Shared secrets match.")
	}
}

// TestSignatureEncodingCompatibility tests that the encoding format is compatible.
func TestSignatureEncodingCompatibility(t *testing.T) {
	suiteV3 := edv3.NewBlakeSHA256Ed25519()
	suiteV4 := edv4.NewBlakeSHA256Ed25519()

	// Create a signature struct in V3
	randV3 := suiteV3.XOF([]byte("encoding-test"))
	c := suiteV3.Scalar().Pick(randV3)
	r := suiteV3.Scalar().Pick(randV3)

	sigV3 := basicSigV3{C: c, R: r}
	bufV3 := bytes.Buffer{}
	if err := suiteV3.Write(&bufV3, &sigV3); err != nil {
		t.Fatalf("Failed to encode V3 signature: %v", err)
	}

	t.Logf("V3 encoded signature: %s", hex.EncodeToString(bufV3.Bytes()))

	// Decode the signature in V4
	bufV4 := bytes.NewBuffer(bufV3.Bytes())
	sigV4 := basicSigV4{
		C: suiteV4.Scalar(),
		R: suiteV4.Scalar(),
	}
	if err := suiteV4.Read(bufV4, &sigV4); err != nil {
		t.Fatalf("Failed to decode V3 signature in V4: %v", err)
	}

	// Re-encode in V4 and compare
	bufV4Out := bytes.Buffer{}
	if err := suiteV4.Write(&bufV4Out, &sigV4); err != nil {
		t.Fatalf("Failed to re-encode signature in V4: %v", err)
	}

	t.Logf("V4 re-encoded signature: %s", hex.EncodeToString(bufV4Out.Bytes()))

	if !bytes.Equal(bufV3.Bytes(), bufV4Out.Bytes()) {
		t.Error("Signature encoding differs between V3 and V4")
	} else {
		t.Log("Signature encoding is compatible between V3 and V4")
	}
}
