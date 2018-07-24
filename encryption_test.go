package gotools

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestSymmEncr(t *testing.T) {
	text := []byte("Hello World!")
	key := []byte("the-key-has-to-be-32-bytes-long!")

	cipherT, err := SymmEncrypt(key, text)
	assert.Nil(t, err)

	plainT, err := SymmDecrypt(key, cipherT)
	assert.Nil(t, err)

	assert.Equal(t, text, plainT)
}
