# -*- coding: utf-8 -*-
import ed25519
import base64
import base58
import requests
import random
import string
import json
import bottle
import canister
import datetime
import requests
from bottle import response, request, HTTPResponse
import jwt
import uuid
# import did_tool as tool

issuer_port = 3333
app = bottle.Bottle()
app.install(canister.Canister())

global _CREDENTIAL_SUBJECTS
global _VCSCHEME
_CREDENTIAL_SUBJECTS = dict()
_VCSCHEME = dict()
_VCSCHEME ={"driverLicense" : "vc1"}
_ISSUER_DID = "did:mtm:3rfrZgGZHXpjiGr1m3SKAbZSktYudfJCBsoJm4m1XUgp"
_ISSUER_PRIVATEKEY = "4YUNdokj58dyuRQpuoFY2WwCNG47Ermka5XoSFfjhdqZ"
_ISSUER_SECRET = "ExsNKhvF3pqwDvFaVaiQnWWdyeVwxd"
universal_resolver_addr = "https://did-resolver.mitum.com/ddo/" 

def verifyString(string, signStr, pubkey):
    try:
        verifying_key = ed25519.VerifyingKey(base64.b64encode(base58.b58decode(pubkey)),
                                            encoding="base64")
        signedSignature_base58 = signStr
        signedSignature = base58.b58decode(signedSignature_base58)
        verifying_key.verify(signedSignature,
                         string.encode("utf8"),
                         encoding=None)
        return True
    except Exception:
        return False

def generateChallenge(size=32, chars=string.ascii_uppercase + string.digits):
    return ''.join(random.choice(chars) for _ in range(size))

# {URLS} : 1. [GET] Req : VC Schema location
@app.get('/VCScheme')
def VCScheme():
    try:
        scheme = request.query['scheme']
        _VCSCHEME[scheme]
        schemeJSON = json.dumps(
            {
                "scheme": "http://49.50.164.195:8080/v1/scheme?id="+_VCSCHEME[scheme],
                "VCPost": "http://mtm.securekim.com:3333/VC",
                "VCGet" : "http://mtm.securekim.com:3333/VC"
            })
    except Exception:
        response.status = 404
        return "Error"
    print("[이슈어] VC Claim 위치 알려주기 : %s" % (schemeJSON))
    raise HTTPResponse(schemeJSON, status=200, headers={})

def saveCredentialSubject(uuid, credentialSubject):
    _CREDENTIAL_SUBJECTS[uuid] = credentialSubject

def getCredentialSubject(uuid):
    return _CREDENTIAL_SUBJECTS[uuid]

@app.post('/VC')
def VCPost():
    try:
        vc = json.loads(request.body.read())
        myUUID = str(uuid.uuid4())
        did = vc['did']
        credentialSubject = vc['credentialSubject']
        saveCredentialSubject(myUUID, credentialSubject)
        challenge = generateChallenge()
        print("[이슈어] 랜덤 생성한 챌린지 컨텐츠 : %s" % challenge)
        pubkey = getPubkeyFromDIDDocument(did)
        print("[이슈어][document] 도전받는자의 공개키 : %s" % pubkey)
        encoded_jwt = jwt.encode({"uuid": myUUID, "pubkey":pubkey, "challenge":challenge}, _ISSUER_SECRET, algorithm="HS256")
        print("[이슈어] 모바일 헤더에 JWT 발급 : %s" % (encoded_jwt))
    except Exception:
        response.status = 404
        return "Error"
    print("[이슈어] 모바일의 VC 요청 : %s" % (credentialSubject))
    raise HTTPResponse(json.dumps({"payload": challenge, "endPoint":"http://mtm.securekim.com:3333/response"}), status=202, headers={'Authorization':str(encoded_jwt.decode("utf-8"))})

def signString(jsonStr, pk):
    signing_key = ed25519.SigningKey(base58.b58decode(pk))
    sig = signing_key.sign(jsonStr.encode("utf8"), encoding=None)
    sig_base58 = base58.b58encode(sig)
    sig_decoded = sig_base58.decode("utf-8")
    print("[이슈어] 모바일의 페이로드를 사인한 내용 : %s" % sig_decoded )
    return sig_decoded

def makeSampleVC(issuer_did, credentialSubject):
    vc = {
        "@context": [
            "https://www.w3.org/2018/credentials/v1",
            "https://www.w3.org/2018/credentials/examples/v1"
        ],
        "id": " http://mitum.secureKim.com/credentials/3732 ",
        "type": ["VerifiableCredential", "DriverCredential"],
        "issuer": issuer_did,
        "issuanceDate": "2021-06-23T19:73:24Z",
        "credentialSubject": credentialSubject,
        "proof": {
            "type": "Ed25519Signature2018",
            "created": str(datetime.datetime.utcnow().isoformat()),
            "proofPurpose": "assertionMethod", 
            "verificationMethod": "https://secureKim.com/issuers/keys/1"
        }
    }
    return vc

def makeJWS(vc):
    headerJSON = {"alg":"RS256","b64":False,"crit":["b64"]}
    header_base64 = base64.urlsafe_b64encode(json.dumps(headerJSON).encode('utf8'))
    header_ = header_base64.decode('utf8').rstrip("=")
    vcString = json.dumps(vc)
    sig_decoded = signString(vcString, _ISSUER_PRIVATEKEY)
    sig_base64 = base64.urlsafe_b64encode(base58.b58decode(sig_decoded))
    sig_ = sig_base64.decode('utf8').rstrip("=")
    return header_ + ".." + sig_

def getVerifiedJWT(request):
    encoded_jwt = request.headers.get('Authorization')
    print("[이슈어] 모바일의 JWT 토큰 :" + str(encoded_jwt))
    encoded_jwt = encoded_jwt.split(" ")[1] # FROM Bearer
    decoded_jwt = jwt.decode(encoded_jwt, _ISSUER_SECRET, algorithms=["HS256"])
    return decoded_jwt

@app.get('/VC')
def VCGet():
    jwt = getVerifiedJWT(request)
    myUUID = jwt['uuid']
    credentialSubject = getCredentialSubject(myUUID)
    vc = makeSampleVC(_ISSUER_DID, credentialSubject)
    jws = makeJWS(vc)
    vc['proof']["jws"] = jws
    print("[이슈어] 최종 발급된 VC : %s" % vc)
    raise HTTPResponse(json.dumps({"Response":True, "VC": vc}), status=202, headers={})

def getPubkeyFromDIDDocument(did):
    try:
        did_req = requests.get("http://49.50.164.195:8080/v1/DIDDocument?did="+did) 
        pubkey = json.loads(json.loads(did_req.text)['data'])['verificationMethod'][0]['publicKeyBase58']
    except Exception:
        pubkey = "3rfrZgGZHXpjiGr1m3SKAbZSktYudfJCBsoJm4m1XUgp"
    return pubkey

@app.get('/response')
def response():
    #get_body = request.body.read()
    try:
        get_body = request.query['signature']
    except Exception:
        response.status = 400
        return "Error"
    try:
        jwt = getVerifiedJWT(request)
        challengeRet = verifyString(jwt['challenge'] , get_body, jwt['pubkey'])
        print("[이슈어] 받은 사인 값 : %s" % get_body)
        if challengeRet == True:
            print("VC를 만들고, 사인된 VC 보내기")
    except Exception:
        challengeRet = False
    print("[이슈어] 검증 결과 : %s" % challengeRet)
    raise HTTPResponse(json.dumps({"Response": challengeRet}), status=202, headers={})

if __name__ == "__main__":
    #signTest()
    app.run(host='0.0.0.0', port=issuer_port)
