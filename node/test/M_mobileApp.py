# -*- coding: utf-8 -*-

import bottle
import canister
import ed25519
import base58
import json
from ed25519.keys import SigningKey
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

def sign(contentStr):
    signing_key = ed25519.SigningKey(base58.b58decode(my_pk))
    sig = signing_key.sign(contentStr.encode("utf8"), encoding=None)
    print("[모바일앱] 도전자의 페이로드 : %s" % contentStr)
    #sig_decoded = sig.decode("utf8")
    #sig_decoded = sig
    sig_base58 = base58.b58encode(sig)
    sig_decoded = sig_base58.decode("utf-8")
    print("[모바일앱] 도전자의 페이로드를 사인한 내용 : %s" % sig_decoded )
    return sig_decoded

# 1. VC REQUEST : TEST
URL = 'http://127.0.0.1:3333/claimSpec?VCReq=123' 
response = requests.get(URL) 
response.status_code 
response.text
print("[모바일앱] VC Claim Spec Response : %s" % response.text)


URL = 'http://127.0.0.1:3333/challenge?did=did:mtm:Exgfmw6A5RLWWeJX2G4czjLJb8yDxM' 
response = requests.get(URL) 
response.status_code 
response.text
print("[모바일앱] Challenge did Response : %s" % response.text)

data = json.loads(response.text)
signature = sign(data['payload'])

URL = 'http://127.0.0.1:3333/response?signature='+signature 
response = requests.get(URL) 
response.status_code 
response.text
print("[모바일앱] Signature response : %s" % response.text)