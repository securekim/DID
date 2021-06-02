package main

import (
	"crypto/rand"
	"encoding/json"
	"fmt"
	"math/big"
)

func id_generator(n int) (string, error) {
	const letters = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	ret := make([]byte, n)
	for i := 0; i < n; i++ {
		num, err := rand.Int(rand.Reader, big.NewInt(int64(len(letters))))
		if err != nil {
			return "", err
		}
		ret[i] = letters[num.Int64()]
	}

	return string(ret), nil
}

//json to go struct :
//https://mholt.github.io/json-to-go/
type DID_DOC struct {
	Context []string `json:"@context"`
	ID      string   `json:"id"`
	Service []struct {
		Type            string `json:"type"`
		Serviceendpoint string `json:"serviceEndpoint"`
	} `json:"service"`
	Authentication []struct {
		Type      string `json:"type"`
		Publickey string `json:"publicKey"`
	} `json:"authentication"`
	Publickey []struct {
		ID              string `json:"id"`
		Type            string `json:"type"`
		Owner           string `json:"owner"`
		Publickeybase58 string `json:"publicKeyBase58"`
	} `json:"publicKey"`
}

func main() {
	//challenger에서
	// did := "DID: did:mtm:Exgfmw6A5RLWWeJX2G4czjLJb8yDxM"
	// my_pk := "z8ne6htdQaJkE7aaEPvTGZXNt7HDaxjPrgHhTWEX1gnq6ea7vo1WQLMRqfUBws3JZmBgA916aaPic9zcpgUfUZf"

	challenge, err := id_generator(32)
	if err != nil {
		println(err)
	}

	println("[도전자] 랜덤 생성한 챌린지 : " + challenge)

	json_did_doc := `
	{
        "@context": ["https://w3id.org/did/v1"],
        "id": "did:mtm:Exgfmw6A5RLWWeJX2G4czjLJb8yDxM",
        "service": [{
            "type": "DidAuthService",
            "serviceEndpoint": "http://127.0.0.1:3333"
        }],
        "authentication": [{
            "type": "Ed25519SignatureAuthentication2018",
            "publicKey": "did:mtm:Exgfmw6A5RLWWeJX2G4czjLJb8yDxM#key-1"
        }],
        "publicKey": [{
            "id": "did:mtm:Exgfmw6A5RLWWeJX2G4czjLJb8yDxM#key-1",
            "type": "Ed25519VerificationKey2018",
            "owner": "did:mtm:Exgfmw6A5RLWWeJX2G4czjLJb8yDxM",
            "publicKeyBase58": "3ofzDb2umnCy96yLwTHawjTCfPZNxPiaX3g9SjN9CwGV"
        }]
    }
	`
	var did_doc DID_DOC
	json.Unmarshal([]byte(json_did_doc), &did_doc)
	fmt.Printf("%s, %s", did_doc.Service[0].Serviceendpoint, did_doc.Publickey[0].Publickeybase58)

}
