package gotools

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
)

//SymmEncrypt AES(Advanced Encryption Standard) symmetric encrypting text
//the key size should be 16, 24 or 32 bytes
func SymmEncrypt(key, plainTxt []byte) ([]byte, error) {

	c, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("Failt to create cipher %s", err.Error())
	}

	gcm, err := cipher.NewGCM(c)
	if err != nil {
		return nil, fmt.Errorf("Failt to create cipher mode %s", err.Error())
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}

	return gcm.Seal(nonce, nonce, plainTxt, nil), nil

}

//SymmDecrypt symmetric decrypting cipher
func SymmDecrypt(key, cipherTxt []byte) ([]byte, error) {
	c, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(c)
	if err != nil {
		return nil, err
	}

	nonceSize := gcm.NonceSize()
	if len(cipherTxt) < nonceSize {
		return nil, errors.New("Ciphertext too short")
	}

	nonce, ciphertext := cipherTxt[:nonceSize], cipherTxt[nonceSize:]
	return gcm.Open(nil, nonce, ciphertext, nil)
}
