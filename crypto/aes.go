package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/json"
	"go.dedis.ch/cs438/types"
	"io"
)


func Encrypt(key []byte, plaintext []byte) ([]byte, error) {
	c, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(c)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}

	return gcm.Seal(nonce, nonce, plaintext, nil), nil
}

func Decrypt(key []byte, ciphertext []byte) ([]byte, error) {
	c, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(c)
	if err != nil {
		return nil, err
	}

	nonceSize := gcm.NonceSize()
	if len(ciphertext) < nonceSize {
		return nil, err
	}

	nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, err
	}
	return plaintext, nil
}

func EncryptMsg(key []byte, msg types.Message) ([]byte, error) {
	bytes, err := json.Marshal(msg)
	if err != nil {
		return nil, err
	}

	return Encrypt(key, bytes)
}

func DecryptMsg(key []byte, bytes []byte) (types.Message, error) {
	plaintext, err := Decrypt(key, bytes)
	if err != nil {
		return nil, err
	}

	var msg types.Message
	err = json.Unmarshal(plaintext, &msg)
	return msg, err
}
