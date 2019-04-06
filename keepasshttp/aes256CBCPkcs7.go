package keepasshttp

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
)

type aes256CBCPksc7 struct {
	key []byte
	iv  []byte
}

// NewAES256CBCPksc7 is an simple helper to do AES256 encryption/decryption.
func NewAES256CBCPksc7(key []byte, iv []byte) (aes256cbc *aes256CBCPksc7, err error) {
	if key == nil {
		key, _ = aes256cbc.randBytes(32)
	} else if len(key) < 32 {
		err = aes.KeySizeError(len(key))
		return
	} else if len(key) > 32 {
		key = key[:32]
	}

	if iv == nil {
		iv, _ = aes256cbc.randBytes(16)
	} else if len(iv) < 16 {
		err = aes.KeySizeError(len(iv))
		return
	} else if len(iv) > 16 {
		iv = iv[:16]
	}

	aes256cbc = &aes256CBCPksc7{key: key, iv: iv}
	return
}

func (aes256 *aes256CBCPksc7) randBytes(size int) (randBytes []byte, err error) {
	if size <= 0 {
		err = fmt.Errorf("invalid byte size %d", size)
		return
	}
	randBytes = make([]byte, size)
	_, err = rand.Read(randBytes)
	return
}

func (aes256 *aes256CBCPksc7) encrypt(plain []byte) (cipherText []byte, err error) {
	defer func() { // prevent aes module from panicking and return an error instead
		if r := recover(); r != nil {
			err = fmt.Errorf("AES encryption failed (detail: %s)", r)
		}
	}()
	block, err := aes.NewCipher(aes256.key[:])
	if err != nil {
		return
	}
	stream := cipher.NewCBCEncrypter(block, aes256.iv[:])
	paddedPlain := aes256.pad(plain)
	cipherText = make([]byte, len(paddedPlain))
	stream.CryptBlocks(cipherText, paddedPlain)
	return
}

func (aes256 *aes256CBCPksc7) decrypt(cipherText []byte) (plain []byte, err error) {
	defer func() { // prevent aes module from panicking and return an error instead
		if r := recover(); r != nil {
			err = fmt.Errorf("AES decryption failed (detail: %s)", r)
		}
	}()

	block, err := aes.NewCipher(aes256.key[:])
	if err != nil {
		return
	}

	paddedPlain := make([]byte, len(cipherText))
	stream := cipher.NewCBCDecrypter(block, aes256.iv[:])
	stream.CryptBlocks(paddedPlain, cipherText)

	plain = aes256.unpad(paddedPlain)
	return
}

func (aes256 *aes256CBCPksc7) pad(data []byte) []byte {
	padlen := 16 - (len(data) % 16)
	pad := bytes.Repeat([]byte{byte(padlen)}, padlen)
	return append(data, pad...)
}

func (aes256 *aes256CBCPksc7) unpad(data []byte) []byte {
	padlen := int(data[len(data)-1])
	if padlen > 16 {
		padlen = 0
	}
	return data[:len(data)-padlen]
}
