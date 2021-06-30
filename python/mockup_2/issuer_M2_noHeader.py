# -*- coding: utf-8 -*-
import ed25519
import base64
import base58
import requests
import random
import string
import sys
import json
import re
import bottle
import canister
import time
import requests
from bottle import response, request, HTTPResponse
from multiprocessing import Process
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs

my_port = 3333
#challenge_global = ""
#pubkey_global = ""
app = bottle.Bottle()
app.install(canister.Canister())

#if len(sys.argv[1:]) < 1:
#    sys.exit("[이슈어] 도전받는자의 DID가 필요함)
#challengee_did = str(sys.argv[1:][0])

issuerDID = "did:mtm:3rfrZgGZHXpjiGr1m3SKAbZSktYudfJCBsoJm4m1XUgp"
challengee_did = "did:mtm:ExsNKhvF3pqwDvFaVaiQnWWdyeVwxd"
my_pk = "4YUNdokj58dyuRQpuoFY2WwCNG47Ermka5XoSFfjhdqZ"

pattern = re.compile("^did:mtm:[a-km-zA-HJ-NP-Z1-9]{30,30}$")
if not pattern.match(challengee_did):
    sys.exit("Invalid DID provided")
universal_resolver_addr = "https://did-resolver.mitum.com/ddo/" # universal resolver를 사용하는 경우

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

def callback_http(s):
    s.serve_forever()

# challenge generation function
def id_generator(size=32, chars=string.ascii_uppercase + string.digits):
    return ''.join(random.choice(chars) for _ in range(size))

# {URLS} : 1. [GET] Req : VC Schema location
@app.get('/VCScheme')
def VCScheme():
    try:
        scheme = request.query['scheme']
        schemeJSON = json.dumps(
            {
                "scheme": "49.50.164.195:8080/v1/scheme?id="+scheme,
                "VCPost": "http://mtm.securekim.com:3333/VC",
                "VCGet" : "http://mtm.securekim.com:3333/VC"
            })
    except Exception:
        response.status = 404
        return "Error"
    print("[이슈어] VC Claim 위치 알려주기 : %s" % (schemeJSON))
    raise HTTPResponse(schemeJSON, status=200, headers={})

@app.post('/VC')
def VCPost():
    try:
        global vc1 
        global challenge_global
        global pubkey_global
        global credentialSubject
        vc1 = json.loads(request.body.read())
        did = vc1['did']
        credentialSubject = vc1['credentialSubject']
        challenge_global, pubkey_global = challenging(did)
    except Exception:
        response.status = 404
        return "Error"
    print("[이슈어] 모바일의 VC 요청 : %s" % (credentialSubject))
    raise HTTPResponse(json.dumps({"payload": challenge_global}), status=202, headers={})

def signJSON(jsonStr, pk):
    signing_key = ed25519.SigningKey(base58.b58decode(pk))
    sig = signing_key.sign(jsonStr.encode("utf8"), encoding=None)
    # print("[이슈어] 모바일의 페이로드 : %s" % jsonStr)
    #sig_decoded = sig.decode("utf8")
    #sig_decoded = sig
    sig_base58 = base58.b58encode(sig)
    sig_decoded = sig_base58.decode("utf-8")
    print("[이슈어] 모바일의 페이로드를 사인한 내용 : %s" % sig_decoded )
    return sig_decoded

@app.get('/VC')
def VCGet():
    issuerJSON = {
        "@context": [
            "https://www.w3.org/2018/credentials/v1",
            "https://www.w3.org/2018/credentials/examples/v1"
        ],
        "id": " http://mitum.secureKim.com/credentials/3732 ",
        "type": ["VerifiableCredential", "DriverCredential"],
        "issuer": issuerDID,
        "issuanceDate": "2021-06-23T19:73:24Z",
        "credentialSubject": credentialSubject,
        "proof": {
            "type": "Ed25519Signature2018",
            "created": "2017-06-24T21:19:10Z",
            "proofPurpose": "assertionMethod", 
            "verificationMethod": "https://secureKim.com/issuers/keys/1"
        }
    }
    issuerJSONStr = json.dumps(issuerJSON) # JSON TO STRING
    #json.loads(json_string) # STRING TO JSON 
    sig_decoded = signJSON(issuerJSONStr, my_pk)
    sig_base64 = base64.urlsafe_b64encode(base58.b58decode(sig_decoded))
    header = {"alg":"RS256","b64":False,"crit":["b64"]}
    header_base64 = base64.urlsafe_b64encode(json.dumps(header).encode('utf8'))
    issuerJSON['proof']["jws"] = header_base64.decode('utf8').rstrip("=")+".."+sig_base64.decode('utf8').rstrip("=")
    print("[이슈어] 최종 발급된 VC : %s" % issuerJSON)
    raise HTTPResponse(json.dumps({"Response":True, "VC": issuerJSON}), status=202, headers={})

def challenging(did):
    challenge = id_generator()
    try:
        did_req = requests.get("http://49.50.164.195:8080/v1/DIDDocument?did="+did) 
        pubkey = json.loads(json.loads(did_req.text)['data'])['verificationMethod'][0]['publicKeyBase58']
    except Exception:
        pubkey = "3rfrZgGZHXpjiGr1m3SKAbZSktYudfJCBsoJm4m1XUgp"
    print("[이슈어] 랜덤 생성한 챌린지 컨텐츠 : %s" % challenge)
    print("[이슈어][document] 도전받는자의 공개키 : %s" % pubkey)
    pubkey_global = pubkey
    challenge_global = challenge
    return challenge_global, pubkey_global

@app.get('/challenge')
def challenge():
    #get_body = request.body.read()
    global challenge_global
    global pubkey_global
    try:
        get_body = request.query['did']
        challenge_global, pubkey_global = challenging(get_body)
        print("[GET CHALLENGE] : Challenge : %s, pubkey : %s" %(challenge_global, pubkey_global))
    except Exception:
        print("[GET CAHLLENGE] ERROR")
        response.status = 400
        return "Error"
    raise HTTPResponse(json.dumps({"payload": challenge_global}), status=202, headers={})
    #challenging(get_body)

@app.get('/response')
def response():
    #get_body = request.body.read()
    try:
        get_body = request.query['signature']
    except Exception:
        response.status = 400
        return "Error"
    try:
        challengeRet = verifyString(challenge_global, get_body, pubkey_global)
        print("[이슈어] 받은 사인 값 : %s" % get_body)
        if challengeRet == True:
            print("VC를 만들고, 사인된 VC 보내기")
    except Exception:
        challengeRet = False
    print("[이슈어] 검증 결과 : %s" % challengeRet)
    raise HTTPResponse(json.dumps({"Response": challengeRet}), status=202, headers={})

@app.get('/claim')
def response():
    try:
        get_body = request.query['VCReq']
    except Exception:
        response.status = 400
        return "Error"
    raise HTTPResponse(json.dumps({
            "iss": "did:mtm:serverdid",
            "@context": ["https://www.w3.org/2018/credentials/v1","https://www.w3.org/2018/credentials/examples/v1"],
            "type": "VCReq",
            "claims": {
                "selfie": { "essential": True, "reason": "For photo identification"},
                "name": {"essential": True, "reason": "For ID"},
                "amount": {"essential": False, "reason": "null"},
                "email" : {"essential": True, "reason": "We need to be able to email you"}
            }
        }
    ), status=202, headers={})
    

if __name__ == "__main__":
    #signTest()
    app.run(host='0.0.0.0', port=my_port)

#http://172.28.91.165:3333/challenge?did=did:mtm:DTxegdAVdSe9WL1tS7AZ3bEs4dXn1XZnSboP7NRXAjb6
#http://172.28.91.165:3333/response?signature=abcdef


#http://mitum.securekim.com:3333/challenge?did=did:mtm:DTxegdAVdSe9WL1tS7AZ3bEs4dXn1XZnSboP7NRXAjb6
#http://wiggler.securekim.com:3333/response?signature=abcdef