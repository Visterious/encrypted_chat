package crypt

import (
	"io"
	"bytes"
	"crypto"
	"crypto/aes"
	"crypto/rsa"
	"crypto/rand"
	"crypto/x509"
	"crypto/sha256"
	"crypto/cipher"
	"encoding/pem"
	"encoding/hex"
	"./utils"
)

func SessionKey(max int) []byte {
	var slice []byte = make([]byte, max)
	_, err := rand.Read(slice)
	if err != nil { return nil }
	for max = max - 1; max >= 0; max-- {
		slice[max] = slice[max] % 94 + 33
	}
	return slice
}

func HashSum(data []byte) []byte {
	var hashed = sha256.Sum256(data)
	return hashed[:]
}

func GenerateKeys(bits int) (*rsa.PrivateKey,
*rsa.PublicKey) {
	priv, err := rsa.GenerateKey(rand.Reader, bits)
	utils.CheckError(err)
	return priv, &priv.PublicKey
}

func EncryptRSA(data []byte, pub *rsa.PublicKey) ([]byte, error) {
	return rsa.EncryptOAEP(sha256.New(), rand.Reader, pub, data, nil)
}

func DecryptRSA(data []byte, priv *rsa.PrivateKey) ([]byte, error) {
	return rsa.DecryptOAEP(sha256.New(), rand.Reader, priv, data, nil)
}

func SignRSA(priv *rsa.PrivateKey, data []byte) ([]byte, error) {
	return rsa.SignPSS(rand.Reader, priv, crypto.SHA256,
HashSum(data), nil)
}

func VerifyRSA(pub *rsa.PublicKey, data, sign []byte) error {
	return rsa.VerifyPSS(pub, crypto.SHA256, HashSum(data),
sign, nil)
}

func EncodePrivate(priv *rsa.PrivateKey) []byte {
	return pem.EncodeToMemory(
		&pem.Block{
			Type: "RSA PRIVATE KEY",
			Bytes: x509.MarshalPKCS1PrivateKey(priv),
		},
	)
}

func EncodePublic(pub *rsa.PublicKey) []byte {
	return pem.EncodeToMemory(
		&pem.Block{
			Type: "RSA PUBLIC KEY",
			Bytes: x509.MarshalPKCS1PublicKey(pub),
		},
	)
}

func DecodePrivate(data string) *rsa.PrivateKey {
	block, _ := pem.Decode([]byte(data))

	priv, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	utils.CheckError(err)

	return priv
}

func DecodePublic(data string) *rsa.PublicKey {
	block, _ := pem.Decode([]byte(data))

	pub, err := x509.ParsePKCS1PublicKey(block.Bytes)
	utils.CheckError(err)

	return pub
}

func EncryptAES(data, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}
	blockSize := block.BlockSize()
	data = PKCS5Padding(data, blockSize)

	cipherText := make([]byte, blockSize + len(data))

	iv := cipherText[:blockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		panic(err)
	}

	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(cipherText[blockSize:], data)

	return cipherText, nil
}

func DecryptAES(data, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}
	blockSize := block.BlockSize()

	if len(data) < blockSize {
		panic("ciphertext too short")
	}

	iv := data[:blockSize]
	data = data[blockSize:]
	if len(data) % blockSize != 0 {
		panic("ciphertext is not a multiple of the block size")
	}

	mode := cipher.NewCBCDecrypter(block, iv)
	mode.CryptBlocks(data, data)

	return PKCS5Unpadding(data), nil
}

func Encrypt(session_key []byte, data string) string {
	result, _ := EncryptAES([]byte(data), session_key)
	return hex.EncodeToString(result)
}

func Decrypt(session_key []byte, data string) string {
	decoded, _ := hex.DecodeString(data)
	result, _ := DecryptAES(decoded, session_key)
	return string(result)
}

func PKCS5Padding(ciphertext []byte, blockSize int) []byte {
	padding := blockSize - len(ciphertext) % blockSize
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(ciphertext, padtext...)
}

func PKCS5Unpadding(origData []byte) []byte {
	length := len(origData)
	unpadding := int(origData[length-1])
	return origData[:(length - unpadding)]
}