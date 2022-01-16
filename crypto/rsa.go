package crypto

import (
	cryp "crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
)

func GenerateKey(keySize int) (*rsa.PrivateKey, error) {
	return rsa.GenerateKey(rand.Reader, keySize)
}

func Sign(data []byte, privateKey *rsa.PrivateKey) ([]byte, error) {
	msgHash := sha256.New()
	_, err := msgHash.Write(data)
	if err != nil {
		return nil, err
	}
	msgHashSum := msgHash.Sum(nil)

	return rsa.SignPSS(rand.Reader, privateKey, cryp.SHA256, msgHashSum, nil)
}

func Verify(data, signature []byte, publicKey *rsa.PublicKey) bool {
	msgHash := sha256.New()
	_, err := msgHash.Write(data)
	if err != nil {
		return false
	}
	msgHashSum := msgHash.Sum(nil)
	return rsa.VerifyPSS(publicKey, cryp.SHA256, msgHashSum, signature, nil) == nil
}
func VerifyErr(data, signature []byte, publicKey *rsa.PublicKey) error {
	msgHash := sha256.New()
	_, err := msgHash.Write(data)
	if err != nil {
		return err
	}
	msgHashSum := msgHash.Sum(nil)
	return rsa.VerifyPSS(publicKey, cryp.SHA256, msgHashSum, signature, nil)
}
