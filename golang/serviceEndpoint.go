package main

import (
	"crypto/ed25519"
	"encoding/ascii85"
	"encoding/hex"
	"net/http"

	"github.com/btcsuite/btcutil/base58"
)

type testHandler struct {
	http.Handler
}

func (h *testHandler) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	str := "Your Request Path is " + req.URL.Path
	w.Write([]byte(str))
}

func sign(content string, privateKey string) []byte {
	rawkey := base58.Decode(privateKey)
	pubkey, privkey, err := ed25519.GenerateKey(nil)
	if err != nil {
		println(err)
	}
	println(rawkey)
	println(privkey)
	println(pubkey)
	src := []byte(content)
	dst := make([]byte, hex.EncodedLen(len(src)))
	hex.Encode(dst, src)
	sig := ed25519.Sign(privkey, dst)
	var ret []byte
	ascii85.Decode(ret, sig, false)
	return ret
}

// func DeserializePrivateKey(data []byte) (pri PrivateKey, err error) {
// 	switch KeyType(data[0]) {
// 	case PK_ECDSA, PK_SM2:
// 		c, err1 := GetCurve(data[1])
// 		if err1 != nil {
// 			err = err1
// 			return
// 		}
// 		size := (c.Params().BitSize + 7) >> 3
// 		if len(data) < size*2+3 {
// 			err = errors.New("deserializing private key failed: not enough length")
// 			return
// 		}

// 		key := &ec.PrivateKey{
// 			Algorithm:  ec.ECDSA,
// 			PrivateKey: ec.ConstructPrivateKey(data[2:2+size], c),
// 		}

// 		p, err1 := ec.DecodePublicKey(data[2+size:], c)
// 		if err1 != nil {
// 			err = fmt.Errorf("deserializing private key failed: %s", err1)
// 			return
// 		}
// 		if key.X.Cmp(p.X) != 0 || key.Y.Cmp(p.Y) != 0 {
// 			err = errors.New("deserializing private key failed: unmatched private and public key")
// 			return
// 		}

// 		switch KeyType(data[0]) {
// 		case PK_ECDSA:
// 			key.Algorithm = ec.ECDSA
// 		case PK_SM2:
// 			key.Algorithm = ec.SM2
// 		}
// 		pri = key

// 	case PK_EDDSA:
// 		if data[1] == ED25519 {
// 			if len(data) < 2+ed25519.PrivateKeySize {
// 				err = errors.New("deserializing private key failed: not enough length for Ed25519 key")
// 				return
// 			}
// 			pri = ed25519.PrivateKey(data[2:])
// 		} else {
// 			err = errors.New("deserializing private key failed: unknown EdDSA curve type")
// 			return
// 		}
// 	}
// 	return
// }

func main() {
	//whoami := "did:mtm:Exgfmw6A5RLWWeJX2G4czjLJb8yDxM"
	my_pk := "z8ne6htdQaJkE7aaEPvTGZXNt7HDaxjPrgHhTWEX1gnq6ea7vo1WQLMRqfUBws3JZmBgA916aaPic9zcpgUfUZf"

	challengersPayload := "4VA4D9PL3APHVPFFEA5XM8CW8P0A4Q8K"

	signed := sign(challengersPayload, my_pk)
	println(signed)
	http.Handle("/.identity/challenge", new(testHandler))
	http.ListenAndServe(":3333", nil)
}
