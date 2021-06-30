# -*- coding: utf-8 -*-
import ed25519
import base64
import base58
import json
clientJSON = {'selfie':'/9j/4AAQSkZJRgABAQAASABIAAD/.....',
'name':'홍길동','amount': 3,'buyAt': '2021-03-23T18:32:23'}
clientDID = "did:mtm:ebfeb1f712ebc6f1c276e12ec21"
print("[이슈어] 모바일의 VC 요청 데이터 : %s" % clientJSON)
clientJSON["clientDID"] = clientDID 
issuerDID = "did:mtm:server"
issuerJSON = {
  "@context": [
    "https://www.w3.org/2018/credentials/v1",
    "https://www.w3.org/2018/credentials/examples/v1"
  ],
  "id": " http://mitum.secureKim.com/credentials/3732 ",
  "type": ["VerifiableCredential", "DriverCredential"],
  "issuer": "did:mtm:server",
  "issuanceDate": "2021-06-23T19:73:24Z",
  "credentialSubject": clientJSON,
  "proof": {
    "type": "Ed25519Signature2018",
    "created": "2017-06-24T21:19:10Z",
    "proofPurpose": "assertionMethod", 
    "verificationMethod": "https://secureKim.com/issuers/keys/1"
  }
}

issuerJSONStr = json.dumps(issuerJSON) # JSON TO STRING
#json.loads(json_string) # STRING TO JSON 

my_pk = "4YUNdokj58dyuRQpuoFY2WwCNG47Ermka5XoSFfjhdqZ"
def signJSON(jsonStr):
    signing_key = ed25519.SigningKey(base58.b58decode(my_pk))
    sig = signing_key.sign(jsonStr.encode("utf8"), encoding=None)
    print("[이슈어] 모바일의 페이로드 : %s" % jsonStr)
    #sig_decoded = sig.decode("utf8")
    #sig_decoded = sig
    sig_base58 = base58.b58encode(sig)
    sig_decoded = sig_base58.decode("utf-8")
    print("[이슈어] 모바일의 페이로드를 사인한 내용 : %s" % sig_decoded )
    return sig_decoded

sig_decoded = signJSON(issuerJSONStr)
pubkey = "3rfrZgGZHXpjiGr1m3SKAbZSktYudfJCBsoJm4m1XUgp"

def verifyString(challenge, sigStr, pubkey):
    try:
        verifying_key = ed25519.VerifyingKey(base64.b64encode(base58.b58decode(pubkey)),
                                            encoding="base64")
        signedSignature_base58 = sigStr
        signedSignature = base58.b58decode(signedSignature_base58)
        verifying_key.verify(signedSignature,
                         challenge.encode("utf8"),
                         encoding=None)
        return True
    except Exception:
        return False

ret = verifyString(issuerJSONStr,sig_decoded,pubkey)
print("[검증자] VC 검증 결과 :",ret)