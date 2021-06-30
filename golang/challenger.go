package main

import (
	"bytes"
	"crypto/rand"
	"encoding/json"
	"io/ioutil"
	"math/big"
	"net/http"
)

var challengeCallback string

func id_generator() (string, error) {
	n := 32
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

//Person -
type Challenge struct {
	payload  string
	callback string
}

func do_Challenge_Post(url string, challenge Challenge) string {
	pbytes, _ := json.Marshal(challenge)
	buff := bytes.NewBuffer(pbytes)
	resp, err := http.Post(url, "application/json", buff)

	if err != nil {
		panic(err)
	}
	defer resp.Body.Close()
	// Response 체크.
	respBody, err := ioutil.ReadAll(resp.Body)
	if err == nil {
		str := string(respBody)
		//println(str)
		return str
	}
	return ""
}

func main() {
	//challenger에서
	// did := "DID: did:mtm:Exgfmw6A5RLWWeJX2G4czjLJb8yDxM"
	// my_pk := "z8ne6htdQaJkE7aaEPvTGZXNt7HDaxjPrgHhTWEX1gnq6ea7vo1WQLMRqfUBws3JZmBgA916aaPic9zcpgUfUZf"

	challenge, err := id_generator()
	if err != nil {
		println(err)
	}

	println("[도전자] 랜덤 생성한 챌린지 컨텐츠 : " + challenge)

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
	println("[도전자][document] 도전받는자의 서비스 엔드포인트 : ", did_doc.Service[0].Serviceendpoint)
	println("[도전자][document] 도전받는자의 공개키 : ", did_doc.Publickey[0].Publickeybase58)

	// 콜백 핸들용 랜덤 주소 생성
	callback_id, err := id_generator()

	var challenge_data Challenge
	challenge_data.payload = challenge
	challenge_data.callback = "http://127.0.0.1:4444/callback?" + callback_id
	challengee_url := did_doc.Service[0].Serviceendpoint + "/.identity/challenge"

	println("[도전자] 내 챌린지(페이로드) : ", challenge_data.payload)
	println("[도전자] 내 챌린지(콜백) : ", challenge_data.callback)
	println("[도전자] 도전받는자의 주소 : ", challengee_url)

	resp := do_Challenge_Post(challengee_url, challenge_data)
	println("[도전자][callback] 도전 받는자의 페이로드(사인): ", resp)

}
