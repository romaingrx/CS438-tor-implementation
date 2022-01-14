package crypto

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
)

func GenerateKey(keySize int) (*rsa.PrivateKey, error) {
	return rsa.GenerateKey(rand.Reader, keySize)
}

func Sign(data []byte, privateKey *rsa.PrivateKey) ([]byte, error) {
	hashedData := sha256.Sum256(data)

	signature, err := rsa.SignPSS(rand.Reader, privateKey, crypto.SHA256, hashedData[:], nil)
	if err != nil {
		return nil, err
	}

	return signature, nil
}

func Verify(data, signature []byte, publicKey *rsa.PublicKey) bool {
	return rsa.VerifyPSS(publicKey, crypto.SHA256, data, signature, nil) == nil
}