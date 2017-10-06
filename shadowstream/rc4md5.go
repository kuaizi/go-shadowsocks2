package shadowstream

import (
	"crypto/cipher"
	"crypto/md5"
	"crypto/rc4"
)

type rc4Md5Key []byte

func (k rc4Md5Key) IVSize() int {
	return 16
}

func (k rc4Md5Key) Encrypter(iv []byte) cipher.Stream {
	h := md5.New()
	h.Write([]byte(k))
	h.Write(iv)
	rc4key := h.Sum(nil)
	c, _ := rc4.NewCipher(rc4key)
	return c
}

func (k rc4Md5Key) Decrypter(iv []byte) cipher.Stream {
	return k.Encrypter(iv)
}

func RC4MD5(key []byte) (Cipher, error) {
	k := rc4Md5Key(key)
	return k, nil
}
