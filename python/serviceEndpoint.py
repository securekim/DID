# -*- coding: utf-8 -*-

import bottle
import ed25519
import base58
import json
import canister
import requests
from bottle import response, request, HTTPResponse
from multiprocessing import Process
from os import environ

if environ.get('WHOAMI') is not None:
    whoami = environ.get('WHOAMI')
else:
    whoami = "did:mtm:Exgfmw6A5RLWWeJX2G4czjLJb8yDxM"

if environ.get('MY_PRIVATE_KEY') is not None:
    my_pk = environ.get('MY_PRIVATE_KEY')
else:
    my_pk = "4YUNdokj58dyuRQpuoFY2WwCNG47Ermka5XoSFfjhdqZ"

if environ.get('PORT') is not None:
    my_port = environ.get('PORT')
else:
    my_port = 3333

app = bottle.Bottle()
app.install(canister.Canister())

def sign(content):
    signing_key = ed25519.SigningKey(base58.b58decode(my_pk))
    sig = signing_key.sign(content["payload"].encode("utf8"), encoding=None)
    print("[도전받는자] 도전자의 페이로드 : %s" % content["payload"])
    #sig_decoded = sig.decode("utf8")
    #sig_decoded = sig
    sig_base58 = base58.b58encode(sig)
    sig_decoded = sig_base58.decode("utf-8")
    print("[도전받는자] 도전자의 페이로드를 사인한 내용 : %s" % sig_decoded )
    return sig_decoded

def signTest():
    payload = "Hello world"
    signing_key = ed25519.SigningKey(base58.b58decode(my_pk))
    sig = signing_key.sign(payload.encode("utf8"), encoding=None)
    #sig_decoded = sig.decode("utf8")
    sig_base58 = base58.b58encode(sig)
    print("[테스트] 헬로월드 페이로드를 사인한 내용 : %s" % sig)
    print("[테스트] 헬로월드 페이로드를 사인해서 base58 : %s" % sig_base58)


def response(resp, req):
    print("[도전받는자] 도전자 콜백 주소 %s 로 메시지 보냄 : %s" %(req["callback"], resp))
    r = requests.post(req["callback"], data=resp)
    print("[도전받는자] 도전자의 콜백 응답 %s" % r.status_code + ": " + r.text)

@app.post('/.identity/challenge')
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
