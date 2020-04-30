package util

import (
	"crypto/aes"
	"crypto/cipher"
)

func newAead(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return aead, nil
}

func E(plain []byte, key, nonce []byte) []byte {
	aead, err := newAead(key)
	if err != nil {
		println(err.Error())
		return nil
	}

	return aead.Seal(plain[:0], nonce, plain, nil)
}

func D(cipher []byte, key, nonce []byte) []byte {
	aead, err := newAead(key)
	if err != nil {
		println(err.Error())
		return nil
	}

	output, err := aead.Open(cipher[:0], nonce, cipher, nil)
	if err != nil {
		println(err.Error())
		return nil
	}

	return output
}
