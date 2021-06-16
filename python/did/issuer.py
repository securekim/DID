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
#    sys.exit("[검증자] 도전받는자의 DID가 필요함)
#challengee_did = str(sys.argv[1:][0])

challengee_did = "did:mtm:ExsNKhvF3pqwDvFaVaiQnWWdyeVwxd"

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

def challenging(did):
    challenge = id_generator()
    try:
        did_req = requests.get("http://49.50.164.195:8080/v1/DIDDocument?did="+did) 
        pubkey = json.loads(json.loads(did_req.text)['data'])['verificationMethod'][0]['publicKeyBase58']
    except Exception:
        pubkey = "3rfrZgGZHXpjiGr1m3SKAbZSktYudfJCBsoJm4m1XUgp"
    print("[검증자] 랜덤 생성한 챌린지 컨텐츠 : %s" % challenge)
    print("[검증자][document] 도전받는자의 공개키 : %s" % pubkey)
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
    except Exception:
        response.status = 400
        return "Error"
    print(challenge_global)
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
        print("[검증자] 받은 사인 값 : %s" % get_body)
    except Exception:
        challengeRet = False
    print("[검증자] 검증 결과 : %s" % challengeRet)
    raise HTTPResponse(json.dumps({"Response": challengeRet}), status=202, headers={})

#http://127.0.0.1:3333/claim?VCReq=123
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
    
@app.post('/claim')
def challenge():
    post_body = request.body.read()
    try:
        req = json.loads(post_body)
    except Exception:
        response.status = 400
        return "Malformed request"
    sig = sign(req)
    resp = json.dumps({"payload": sig})
    if "callback" in req:
        p = Process(target=response, args=(resp, req,))
        p.start()

        response.status = 202
        raise HTTPResponse(json.dumps({"payload": "202 Accepted"}), status=202, headers={})
    else:
        return resp

if __name__ == "__main__":
    #signTest()
    app.run(host='0.0.0.0', port=my_port)

#http://172.28.91.165:3333/challenge?did=did:mtm:DTxegdAVdSe9WL1tS7AZ3bEs4dXn1XZnSboP7NRXAjb6
#http://172.28.91.165:3333/response?signature=abcdef


#http://mitum.securekim.com:3333/challenge?did=did:mtm:DTxegdAVdSe9WL1tS7AZ3bEs4dXn1XZnSboP7NRXAjb6
#http://wiggler.securekim.com:3333/response?signature=abcdef