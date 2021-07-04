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
import did_tool as DID

_url = DID.SAMPLE['issuer']['url']

app = bottle.Bottle()
app.install(canister.Canister())

# 1.[GET] Req : VC Scheme location
URL = _url+'/VCScheme?scheme=driverLicense' 
response = requests.get(URL) 
print("[모바일앱] VC Claim 위치 : %s : %s" % (response.status_code, response.text))
data = json.loads(response.text)
VCGet = data['VCGet']
VCPost = data['VCPost']

# 2.[POST] Req : DID & VC
URL = VCPost
data = {'did': DID.SAMPLE['holder']['did'],
'credentialSubject':DID.SAMPLE['holder']['credentialSubject']} 
response = requests.post(URL, data=json.dumps(data))
jwt = response.headers.get('Authorization')
print("[모바일앱] DID : %s, VC Data : %s, JWT : %s" % (data['did'], data, jwt))

data = json.loads(response.text)
signature = DID.signString(data['payload'], DID.SAMPLE['holder']['privateKey'])

# 3.[GET] Req : Challenge & Response 
URL = data['endPoint'] + '?signature='+signature 
response = requests.get(URL, headers={'Authorization':'Bearer ' + str(jwt)}) 
print("[모바일앱] DID Auth 결과 : %s" % response.text)

# 4.[GET] Req : VC
URL = VCGet
response = requests.get(URL, headers={'Authorization':'Bearer ' + str(jwt)}) 
print("[모바일앱] VC 발급 결과 : %s" % response.text)
