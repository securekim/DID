# -*- coding: utf-8 -*-

import bottle
import canister
import ed25519
import base58
import json
from ed25519.keys import SigningKey
import requests
from bottle import response, request, HTTPResponse
from os import environ

_test_url = "http://127.0.0.1:3333"
_test_privateKey = "4YUNdokj58dyuRQpuoFY2WwCNG47Ermka5XoSFfjhdqZ"


if environ.get('WHOAMI') is not None:
    whoami = environ.get('WHOAMI')
else:
    whoami = "did:mtm:Exgfmw6A5RLWWeJX2G4czjLJb8yDxM"

if environ.get('MY_PRIVATE_KEY') is not None:
    _test_privateKey = environ.get('MY_PRIVATE_KEY')
else:
    _test_privateKey = "4YUNdokj58dyuRQpuoFY2WwCNG47Ermka5XoSFfjhdqZ"

if environ.get('PORT') is not None:
    my_port = environ.get('PORT')
else:
    my_port = 3333

app = bottle.Bottle()
app.install(canister.Canister())

def sign(contentStr):
    signing_key = ed25519.SigningKey(base58.b58decode(_test_privateKey))
    sig = signing_key.sign(contentStr.encode("utf8"), encoding=None)
    print("[모바일앱] 이슈어의 페이로드 : %s" % contentStr)
    #sig_decoded = sig.decode("utf8")
    #sig_decoded = sig
    sig_base58 = base58.b58encode(sig)
    sig_decoded = sig_base58.decode("utf-8")
    print("[모바일앱] 이슈어의 페이로드를 사인한 내용 : %s" % sig_decoded )
    return sig_decoded

# 1.[GET] Req : VC Scheme location
URL = _test_url+'/VCScheme?scheme=vc1' 
response = requests.get(URL) 
response.status_code 
response.text
print("[모바일앱] VC Claim 위치 : %s : %s" % (response.status_code, response.text))

# 2.[POST] Req : DID & VC
URL = _test_url+'/VC' 
data = {'did': 'did:mtm:Exgfmw6A5RLWWeJX2G4czjLJb8yDxM',
'credentialSubject':{'selfie':'/9j/4AAQSkZJRgABAQAASABIAAD/.....',
'name':'홍길동','amount': 3,'buyAt': '2021-03-23T18:32:23'}} 
response = requests.post(URL, data=json.dumps(data))
print("[모바일앱] DID : %s, VC Data : %s" % (data['did'], data))

data = json.loads(response.text)
signature = sign(data['payload'])

# 3.[GET] Req : Challenge Response 
URL = _test_url + '/response?signature='+signature 
response = requests.get(URL) 
response.status_code 
response.text
print("[모바일앱] DID Auth 결과 : %s" % response.text)

# 4.[GET] Req : VC
URL = _test_url+'/VC' 
response = requests.get(URL) 
response.status_code 
response.text
print("[모바일앱] VC 발급 결과 : %s" % response.text)

#string += '=' * (-len(string) % 4)
# print("[모바일앱] 발급받은 VC 검증하기: %s" % response.text)