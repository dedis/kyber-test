package kyber

import (
	"github.com/stretchr/testify/require"
	eciesv3 "go.dedis.ch/kyber/v3/encrypt/ecies"
	edwards25519v3 "go.dedis.ch/kyber/v3/group/edwards25519"
	eciesv4 "go.dedis.ch/kyber/v4/encrypt/ecies"
	edwards25519v4 "go.dedis.ch/kyber/v4/group/edwards25519"

	"testing"
)

func EncryptMessage(message []byte, secretInt64 int64, version uint) ([]byte, error) {
	switch version {
	case 3:
		suiteV3 := edwards25519v3.NewBlakeSHA256Ed25519()
		privateV3 := suiteV3.Scalar().SetInt64(secretInt64)
		publicV3 := suiteV3.Point().Mul(privateV3, nil)
		return eciesv3.Encrypt(suiteV3, publicV3, message, suiteV3.Hash)
	case 4:
		suiteV4 := edwards25519v4.NewBlakeSHA256Ed25519()
		privateV4 := suiteV4.Scalar().SetInt64(secretInt64)
		publicV4 := suiteV4.Point().Mul(privateV4, nil)
		return eciesv4.Encrypt(suiteV4, publicV4, message, suiteV4.Hash)
	default:
		panic("unsupported version")
	}
}

func Decrypt(ciphertext []byte, secretInt64 int64, version uint) ([]byte, error) {
	switch version {
	case 3:
		suiteV3 := edwards25519v3.NewBlakeSHA256Ed25519()
		privateV3 := suiteV3.Scalar().SetInt64(secretInt64)
		return eciesv3.Decrypt(suiteV3, privateV3, ciphertext, suiteV3.Hash)
	case 4:
		suiteV4 := edwards25519v4.NewBlakeSHA256Ed25519()
		privateV4 := suiteV4.Scalar().SetInt64(secretInt64)
		return eciesv4.Decrypt(suiteV4, privateV4, ciphertext, suiteV4.Hash)
	default:
		panic("unsupported version")
	}
}

// TestECIES_V3ToV3 is a control test to make sure encrypting/decrypting in V3 works
func TestECIES_V3ToV3(t *testing.T) {
	// Message to encrypt
	message := []byte("Hello ECIES")
	// Encrypt using V3
	ciphertext, err := EncryptMessage(message, 420, 3)
	require.NoError(t, err)

	// Decrypt using V3
	plaintext, err := Decrypt(ciphertext, 420, 3)
	require.NoError(t, err)
	require.Equal(t, message, plaintext)
}

// TestECIES_V4ToV4 is a control test to make sure encrypting/decrypting in V4 works
func TestECIES_V4ToV4(t *testing.T) {
	// Message to encrypt
	message := []byte("Hello ECIES")
	// Encrypt using V4
	ciphertext, err := EncryptMessage(message, 420, 4)
	require.NoError(t, err)

	// Decrypt using V4
	plaintext, err := Decrypt(ciphertext, 420, 4)
	require.NoError(t, err)
	require.Equal(t, message, plaintext)
}

// TestECIES_V3ToV4 tests that encrypting in V3 and decrypting in V4
// is compatible
func TestECIES_V3ToV4(t *testing.T) {
	// Message to encrypt
	message := []byte("Hello ECIES")
	// Encrypt using V3
	ciphertext, err := EncryptMessage(message, 420, 3)
	require.NoError(t, err)

	// Decrypt using V4
	plaintext, err := Decrypt(ciphertext, 420, 4)
	require.NoError(t, err)
	require.Equal(t, message, plaintext)
}

// TestECIES_V4ToV3 tests that encrypting in V4 and decrypting in V3
// is compatible
func TestECIES_V4ToV3(t *testing.T) {
	// Message to encrypt
	message := []byte("Hello ECIES")

	// Encrypt using V4
	ciphertext, err := EncryptMessage(message, 420, 4)
	require.NoError(t, err)

	// Decrypt using V4
	plaintext, err := Decrypt(ciphertext, 420, 3)
	require.NoError(t, err)
	require.Equal(t, message, plaintext)
}
