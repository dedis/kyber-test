package kyber_test

import (
	"bytes"
	"encoding/hex"
	"testing"

	edv3 "go.dedis.ch/kyber/v3/group/edwards25519"
	edv4 "go.dedis.ch/kyber/v4/group/edwards25519"
)

// TestScalarSerializationV3 tests serialization and deserialization of scalars using v3.
func TestScalarSerializationV3(t *testing.T) {
	suite := edv3.NewBlakeSHA256Ed25519()
	rand := suite.XOF([]byte("test-seed"))

	// Create a random scalar
	scalar := suite.Scalar().Pick(rand)

	// Marshal
	data, err := scalar.MarshalBinary()
	if err != nil {
		t.Fatalf("Failed to marshal scalar: %v", err)
	}

	t.Logf("V3 Scalar serialized: %s", hex.EncodeToString(data))

	// Unmarshal
	scalar2 := suite.Scalar()
	if err := scalar2.UnmarshalBinary(data); err != nil {
		t.Fatalf("Failed to unmarshal scalar: %v", err)
	}

	// Verify they are equal
	if !scalar.Equal(scalar2) {
		t.Error("Deserialized scalar does not match original")
	}
}

// TestScalarSerializationV4 tests serialization and deserialization of scalars using v4.
func TestScalarSerializationV4(t *testing.T) {
	suite := edv4.NewBlakeSHA256Ed25519()
	rand := suite.XOF([]byte("test-seed"))

	// Create a random scalar
	scalar := suite.Scalar().Pick(rand)

	// Marshal
	data, err := scalar.MarshalBinary()
	if err != nil {
		t.Fatalf("Failed to marshal scalar: %v", err)
	}

	t.Logf("V4 Scalar serialized: %s", hex.EncodeToString(data))

	// Unmarshal
	scalar2 := suite.Scalar()
	if err := scalar2.UnmarshalBinary(data); err != nil {
		t.Fatalf("Failed to unmarshal scalar: %v", err)
	}

	// Verify they are equal
	if !scalar.Equal(scalar2) {
		t.Error("Deserialized scalar does not match original")
	}
}

// TestPointSerializationV3 tests serialization and deserialization of points using v3.
func TestPointSerializationV3(t *testing.T) {
	suite := edv3.NewBlakeSHA256Ed25519()
	rand := suite.XOF([]byte("test-seed"))

	// Create a random point (public key)
	privateKey := suite.Scalar().Pick(rand)
	publicKey := suite.Point().Mul(privateKey, nil)

	// Marshal
	data, err := publicKey.MarshalBinary()
	if err != nil {
		t.Fatalf("Failed to marshal point: %v", err)
	}

	t.Logf("V3 Point serialized: %s", hex.EncodeToString(data))

	// Unmarshal
	publicKey2 := suite.Point()
	if err := publicKey2.UnmarshalBinary(data); err != nil {
		t.Fatalf("Failed to unmarshal point: %v", err)
	}

	// Verify they are equal
	if !publicKey.Equal(publicKey2) {
		t.Error("Deserialized point does not match original")
	}
}

// TestPointSerializationV4 tests serialization and deserialization of points using v4.
func TestPointSerializationV4(t *testing.T) {
	suite := edv4.NewBlakeSHA256Ed25519()
	rand := suite.XOF([]byte("test-seed"))

	// Create a random point (public key)
	privateKey := suite.Scalar().Pick(rand)
	publicKey := suite.Point().Mul(privateKey, nil)

	// Marshal
	data, err := publicKey.MarshalBinary()
	if err != nil {
		t.Fatalf("Failed to marshal point: %v", err)
	}

	t.Logf("V4 Point serialized: %s", hex.EncodeToString(data))

	// Unmarshal
	publicKey2 := suite.Point()
	if err := publicKey2.UnmarshalBinary(data); err != nil {
		t.Fatalf("Failed to unmarshal point: %v", err)
	}

	// Verify they are equal
	if !publicKey.Equal(publicKey2) {
		t.Error("Deserialized point does not match original")
	}
}

// TestCrossVersionScalarCompatibility tests that scalars serialized by v3 can be deserialized by v4 and vice versa.
func TestCrossVersionScalarCompatibility(t *testing.T) {
	suiteV3 := edv3.NewBlakeSHA256Ed25519()
	suiteV4 := edv4.NewBlakeSHA256Ed25519()

	// Use the same seed for both versions
	randV3 := suiteV3.XOF([]byte("cross-version-test"))
	randV4 := suiteV4.XOF([]byte("cross-version-test"))

	// Create scalars with the same seed
	scalarV3 := suiteV3.Scalar().Pick(randV3)
	scalarV4 := suiteV4.Scalar().Pick(randV4)

	// Serialize both
	dataV3, err := scalarV3.MarshalBinary()
	if err != nil {
		t.Fatalf("Failed to marshal V3 scalar: %v", err)
	}

	dataV4, err := scalarV4.MarshalBinary()
	if err != nil {
		t.Fatalf("Failed to marshal V4 scalar: %v", err)
	}

	t.Logf("V3 Scalar: %s", hex.EncodeToString(dataV3))
	t.Logf("V4 Scalar: %s", hex.EncodeToString(dataV4))

	// Verify that both serialize to the same bytes
	if !bytes.Equal(dataV3, dataV4) {
		t.Error("V3 and V4 scalars do not serialize to the same bytes")
	}

	// Test V3 -> V4 deserialization
	scalarV3toV4 := suiteV4.Scalar()
	if err := scalarV3toV4.UnmarshalBinary(dataV3); err != nil {
		t.Fatalf("Failed to unmarshal V3 scalar in V4: %v", err)
	}

	// Test V4 -> V3 deserialization
	scalarV4toV3 := suiteV3.Scalar()
	if err := scalarV4toV3.UnmarshalBinary(dataV4); err != nil {
		t.Fatalf("Failed to unmarshal V4 scalar in V3: %v", err)
	}

	// Verify round-trip compatibility
	dataV3toV4, _ := scalarV3toV4.MarshalBinary()
	dataV4toV3, _ := scalarV4toV3.MarshalBinary()

	if !bytes.Equal(dataV3, dataV3toV4) {
		t.Error("V3 scalar deserialized in V4 does not match original bytes")
	}

	if !bytes.Equal(dataV4, dataV4toV3) {
		t.Error("V4 scalar deserialized in V3 does not match original bytes")
	}
}

// TestCrossVersionPointCompatibility tests that points serialized by v3 can be deserialized by v4 and vice versa.
func TestCrossVersionPointCompatibility(t *testing.T) {
	suiteV3 := edv3.NewBlakeSHA256Ed25519()
	suiteV4 := edv4.NewBlakeSHA256Ed25519()

	// Use the same seed for both versions
	randV3 := suiteV3.XOF([]byte("cross-version-point-test"))
	randV4 := suiteV4.XOF([]byte("cross-version-point-test"))

	// Create keypairs with the same seed
	privateKeyV3 := suiteV3.Scalar().Pick(randV3)
	publicKeyV3 := suiteV3.Point().Mul(privateKeyV3, nil)

	privateKeyV4 := suiteV4.Scalar().Pick(randV4)
	publicKeyV4 := suiteV4.Point().Mul(privateKeyV4, nil)

	// Serialize both
	dataV3, err := publicKeyV3.MarshalBinary()
	if err != nil {
		t.Fatalf("Failed to marshal V3 point: %v", err)
	}

	dataV4, err := publicKeyV4.MarshalBinary()
	if err != nil {
		t.Fatalf("Failed to marshal V4 point: %v", err)
	}

	t.Logf("V3 Point: %s", hex.EncodeToString(dataV3))
	t.Logf("V4 Point: %s", hex.EncodeToString(dataV4))

	// Verify that both serialize to the same bytes
	if !bytes.Equal(dataV3, dataV4) {
		t.Error("V3 and V4 points do not serialize to the same bytes")
	}

	// Test V3 -> V4 deserialization
	pointV3toV4 := suiteV4.Point()
	if err := pointV3toV4.UnmarshalBinary(dataV3); err != nil {
		t.Fatalf("Failed to unmarshal V3 point in V4: %v", err)
	}

	// Test V4 -> V3 deserialization
	pointV4toV3 := suiteV3.Point()
	if err := pointV4toV3.UnmarshalBinary(dataV4); err != nil {
		t.Fatalf("Failed to unmarshal V4 point in V3: %v", err)
	}

	// Verify round-trip compatibility
	dataV3toV4, _ := pointV3toV4.MarshalBinary()
	dataV4toV3, _ := pointV4toV3.MarshalBinary()

	if !bytes.Equal(dataV3, dataV3toV4) {
		t.Error("V3 point deserialized in V4 does not match original bytes")
	}

	if !bytes.Equal(dataV4, dataV4toV3) {
		t.Error("V4 point deserialized in V3 does not match original bytes")
	}
}

// TestBasePointSerialization tests that the base point is the same in both versions.
func TestBasePointSerialization(t *testing.T) {
	suiteV3 := edv3.NewBlakeSHA256Ed25519()
	suiteV4 := edv4.NewBlakeSHA256Ed25519()

	// Get base points
	baseV3 := suiteV3.Point().Base()
	baseV4 := suiteV4.Point().Base()

	// Serialize both
	dataV3, err := baseV3.MarshalBinary()
	if err != nil {
		t.Fatalf("Failed to marshal V3 base point: %v", err)
	}

	dataV4, err := baseV4.MarshalBinary()
	if err != nil {
		t.Fatalf("Failed to marshal V4 base point: %v", err)
	}

	t.Logf("V3 Base Point: %s", hex.EncodeToString(dataV3))
	t.Logf("V4 Base Point: %s", hex.EncodeToString(dataV4))

	// Verify that both serialize to the same bytes
	if !bytes.Equal(dataV3, dataV4) {
		t.Error("V3 and V4 base points do not serialize to the same bytes")
	}
}

// TestNullPointSerialization tests that the null (identity) point is the same in both versions.
func TestNullPointSerialization(t *testing.T) {
	suiteV3 := edv3.NewBlakeSHA256Ed25519()
	suiteV4 := edv4.NewBlakeSHA256Ed25519()

	// Get null points
	nullV3 := suiteV3.Point().Null()
	nullV4 := suiteV4.Point().Null()

	// Serialize both
	dataV3, err := nullV3.MarshalBinary()
	if err != nil {
		t.Fatalf("Failed to marshal V3 null point: %v", err)
	}

	dataV4, err := nullV4.MarshalBinary()
	if err != nil {
		t.Fatalf("Failed to marshal V4 null point: %v", err)
	}

	t.Logf("V3 Null Point: %s", hex.EncodeToString(dataV3))
	t.Logf("V4 Null Point: %s", hex.EncodeToString(dataV4))

	// Verify that both serialize to the same bytes
	if !bytes.Equal(dataV3, dataV4) {
		t.Error("V3 and V4 null points do not serialize to the same bytes")
	}
}

// TestScalarOperationsCompatibility tests that scalar operations produce the same results.
func TestScalarOperationsCompatibility(t *testing.T) {
	suiteV3 := edv3.NewBlakeSHA256Ed25519()
	suiteV4 := edv4.NewBlakeSHA256Ed25519()

	// Use the same seed for both versions
	randV3 := suiteV3.XOF([]byte("scalar-ops-test"))
	randV4 := suiteV4.XOF([]byte("scalar-ops-test"))

	// Create two scalars in each version
	aV3 := suiteV3.Scalar().Pick(randV3)
	bV3 := suiteV3.Scalar().Pick(randV3)
	aV4 := suiteV4.Scalar().Pick(randV4)
	bV4 := suiteV4.Scalar().Pick(randV4)

	// Test Add
	sumV3, _ := suiteV3.Scalar().Add(aV3, bV3).MarshalBinary()
	sumV4, _ := suiteV4.Scalar().Add(aV4, bV4).MarshalBinary()
	if !bytes.Equal(sumV3, sumV4) {
		t.Error("Scalar addition produces different results in V3 and V4")
	}

	// Test Mul
	prodV3, _ := suiteV3.Scalar().Mul(aV3, bV3).MarshalBinary()
	prodV4, _ := suiteV4.Scalar().Mul(aV4, bV4).MarshalBinary()
	if !bytes.Equal(prodV3, prodV4) {
		t.Error("Scalar multiplication produces different results in V3 and V4")
	}

	// Test Sub
	diffV3, _ := suiteV3.Scalar().Sub(aV3, bV3).MarshalBinary()
	diffV4, _ := suiteV4.Scalar().Sub(aV4, bV4).MarshalBinary()
	if !bytes.Equal(diffV3, diffV4) {
		t.Error("Scalar subtraction produces different results in V3 and V4")
	}

	// Test Neg
	negV3, _ := suiteV3.Scalar().Neg(aV3).MarshalBinary()
	negV4, _ := suiteV4.Scalar().Neg(aV4).MarshalBinary()
	if !bytes.Equal(negV3, negV4) {
		t.Error("Scalar negation produces different results in V3 and V4")
	}
}

// TestPointOperationsCompatibility tests that point operations produce the same results.
func TestPointOperationsCompatibility(t *testing.T) {
	suiteV3 := edv3.NewBlakeSHA256Ed25519()
	suiteV4 := edv4.NewBlakeSHA256Ed25519()

	// Use the same seed for both versions
	randV3 := suiteV3.XOF([]byte("point-ops-test"))
	randV4 := suiteV4.XOF([]byte("point-ops-test"))

	// Create scalars and points
	sV3 := suiteV3.Scalar().Pick(randV3)
	sV4 := suiteV4.Scalar().Pick(randV4)

	// Generate points from scalars
	pV3 := suiteV3.Point().Mul(sV3, nil)
	pV4 := suiteV4.Point().Mul(sV4, nil)

	// Serialize and compare
	dataV3, _ := pV3.MarshalBinary()
	dataV4, _ := pV4.MarshalBinary()
	if !bytes.Equal(dataV3, dataV4) {
		t.Error("Point multiplication with base produces different results in V3 and V4")
	}

	// Test Point Add
	s2V3 := suiteV3.Scalar().Pick(randV3)
	s2V4 := suiteV4.Scalar().Pick(randV4)
	p2V3 := suiteV3.Point().Mul(s2V3, nil)
	p2V4 := suiteV4.Point().Mul(s2V4, nil)

	sumPointV3, _ := suiteV3.Point().Add(pV3, p2V3).MarshalBinary()
	sumPointV4, _ := suiteV4.Point().Add(pV4, p2V4).MarshalBinary()
	if !bytes.Equal(sumPointV3, sumPointV4) {
		t.Error("Point addition produces different results in V3 and V4")
	}

	// Test Point Neg
	negPointV3, _ := suiteV3.Point().Neg(pV3).MarshalBinary()
	negPointV4, _ := suiteV4.Point().Neg(pV4).MarshalBinary()
	if !bytes.Equal(negPointV3, negPointV4) {
		t.Error("Point negation produces different results in V3 and V4")
	}
}

// TestMarshalSize tests that MarshalSize returns the same value in both versions.
func TestMarshalSize(t *testing.T) {
	suiteV3 := edv3.NewBlakeSHA256Ed25519()
	suiteV4 := edv4.NewBlakeSHA256Ed25519()

	// Check scalar size
	scalarV3 := suiteV3.Scalar()
	scalarV4 := suiteV4.Scalar()

	scalarSizeV3 := scalarV3.MarshalSize()
	scalarSizeV4 := scalarV4.MarshalSize()

	if scalarSizeV3 != scalarSizeV4 {
		t.Errorf("Scalar MarshalSize differs: V3=%d, V4=%d", scalarSizeV3, scalarSizeV4)
	}
	t.Logf("Scalar MarshalSize: %d bytes", scalarSizeV3)

	// Check point size
	pointV3 := suiteV3.Point()
	pointV4 := suiteV4.Point()

	pointSizeV3 := pointV3.MarshalSize()
	pointSizeV4 := pointV4.MarshalSize()

	if pointSizeV3 != pointSizeV4 {
		t.Errorf("Point MarshalSize differs: V3=%d, V4=%d", pointSizeV3, pointSizeV4)
	}
	t.Logf("Point MarshalSize: %d bytes", pointSizeV3)
}
