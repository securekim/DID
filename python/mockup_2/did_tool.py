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

global _CREDENTIAL_SUBJECTS
global _VCSCHEME
_CREDENTIAL_SUBJECTS = dict()
_VCSCHEME = dict()
_VCSCHEME ={"driverLicense" : "vc1"}

def signString(string, privateKey):
    try:
        signing_key = ed25519.SigningKey(base58.b58decode(privateKey))
        sig = signing_key.sign(string.encode("utf8"), encoding=None)
        sig_base58 = base58.b58encode(sig)
        sig_decoded = sig_base58.decode("utf-8")
        return sig_decoded
    except Exception:
        return None

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

def saveCredentialSubject(uuid, credentialSubject):
    _CREDENTIAL_SUBJECTS[uuid] = credentialSubject

def getCredentialSubject(uuid):
    return _CREDENTIAL_SUBJECTS[uuid]

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

def makeJWS(vc, privateKey):
    headerJSON = {"alg":"RS256","b64":False,"crit":["b64"]}
    header_base64 = base64.urlsafe_b64encode(json.dumps(headerJSON).encode('utf8'))
    header_ = header_base64.decode('utf8').rstrip("=")
    vcString = json.dumps(vc)
    sig_decoded = signString(vcString, privateKey)
    sig_base64 = base64.urlsafe_b64encode(base58.b58decode(sig_decoded))
    sig_ = sig_base64.decode('utf8').rstrip("=")
    return header_ + ".." + sig_

def getVerifiedJWT(request, secret):
    encoded_jwt = request.headers.get('Authorization')
    print("[이슈어] 모바일의 JWT 토큰 :" + str(encoded_jwt))
    encoded_jwt = encoded_jwt.split(" ")[1] # FROM Bearer
    decoded_jwt = jwt.decode(encoded_jwt, secret, algorithms=["HS256"])
    return decoded_jwt

def getPubkeyFromDIDDocument(did):
    try:
        did_req = requests.get("http://49.50.164.195:8080/v1/DIDDocument?did="+did) 
        pubkey = json.loads(json.loads(did_req.text)['data'])['verificationMethod'][0]['publicKeyBase58']
    except Exception:
        pubkey = "3rfrZgGZHXpjiGr1m3SKAbZSktYudfJCBsoJm4m1XUgp"
    return pubkey