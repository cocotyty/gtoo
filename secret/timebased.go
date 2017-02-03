package secret

import (
	"time"
	"crypto/md5"
	"strconv"
	"bytes"
	"encoding/base64"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"errors"
)

var PermFileWrong = errors.New("Perm file is wrong!")
// 将军令原理
type TimeBasedToken struct {
	privateKey *rsa.PrivateKey
	publicKey  *rsa.PublicKey
}

func (secret *TimeBasedToken) SetPrivateKey(data []byte) (error) {
	block, _ := pem.Decode(data)
	if block == nil {
		return PermFileWrong
	}
	key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return err
	}
	secret.privateKey = key
	return nil
}

func (secret *TimeBasedToken) SetPublicKey(data []byte) (error) {
	block, _ := pem.Decode(data)
	if block == nil {
		return PermFileWrong
	}
	key, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return err
	}
	pubKey, ok := key.(*rsa.PublicKey)
	if !ok {
		return PermFileWrong
	}
	secret.publicKey = pubKey
	return nil
}

func (secret *TimeBasedToken) decrypt(text string) (plaintext []byte) {
	cipherText, err := base64.StdEncoding.DecodeString(text)
	data, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, secret.privateKey, cipherText, []byte{})
	if err != nil {
		panic(err)
	}
	return data
}

func (secret *TimeBasedToken) Verify(text string, password string) (bool) {
	current := time.Now().Unix() / 60 / 5
	res1 := md5.Sum([]byte(strconv.FormatInt(current, 10) + password))
	res2 := md5.Sum([]byte(strconv.FormatInt(current-1, 10) + password))
	res3 := md5.Sum([]byte(strconv.FormatInt(current+1, 10) + password))
	plain := secret.decrypt(text)
	return bytes.Equal(res1[:], plain) || bytes.Equal(res2[:], plain) || bytes.Equal(res3[:], plain)
}
func (secret *TimeBasedToken) GenerateToken(password string) (string, error) {
	plainMsg := md5.Sum([]byte(strconv.FormatInt(time.Now().Unix()/60/5, 10) + password))
	cipherText, err := secret.encrypt(plainMsg[:])
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(cipherText), nil
}
func (secret *TimeBasedToken) encrypt(plaintext []byte) ([]byte, error) {
	cipherText, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, secret.publicKey, plaintext, []byte{})
	if err != nil {
		return nil, err
	}
	return cipherText, nil
}
