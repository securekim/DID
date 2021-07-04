# -*- coding: utf-8 -*-
import ed25519
import base64
import base58
import requests
import random
import string
import json
import datetime
import requests
import jwt
import uuid
import logging
import sentry_sdk
from sentry_sdk.integrations.logging import LoggingIntegration

_CREDENTIAL_SUBJECTS = dict()
_VCSCHEME ={"driverLicense" : "vc1"}

def getTime():
    return str(datetime.datetime.utcnow().isoformat())

SAMPLE = {
    "issuer" :{
        "did" :"did:mtm:3rfrZgGZHXpjiGr1m3SKAbZSktYudfJCBsoJm4m1XUgp",
        "privateKey" : "4YUNdokj58dyuRQpuoFY2WwCNG47Ermka5XoSFfjhdqZ",
        "publicKey" : "3rfrZgGZHXpjiGr1m3SKAbZSktYudfJCBsoJm4m1XUgp",
        "secret" : "ExsNKhvF3pqwDvFaVaiQnWWdyeVwxd",
        "url" : "http://127.0.0.1:3333"
    },
    "holder" : {
        "did" : "did:mtm:Exgfmw6A5RLWWeJX2G4czjLJb8yDxM",
        "privateKey" : "4YUNdokj58dyuRQpuoFY2WwCNG47Ermka5XoSFfjhdqZ",
        "publicKey" : "3rfrZgGZHXpjiGr1m3SKAbZSktYudfJCBsoJm4m1XUgp",
        "credentialSubject" : {'selfie':'/9j/4AAQSkZJRgABAQAASABIAAD/.....',
        'name':'홍길동','amount': 3,'buyAt': getTime()} 
    },
    "verifier" :{

    },
    "platform" :{
        'url' : 'http://49.50.164.195:8080',
        "urls" :{
            "scheme" : "http://49.50.164.195:8080/v1/scheme",
            "resolver" : "https://did-resolver.mitum.com/ddo/",
            "document" : "http://49.50.164.195:8080/v1/DIDDocument"
        }
    }
}

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
            "created": getTime(),
            "proofPurpose": "assertionMethod", 
            "verificationMethod": "https://secureKim.com/issuers/keys/1"
        }
    }
    return vc

_level = {
    "debug" : logging.DEBUG,
    "info" : logging.INFO,
    "warning" : logging.WARNING,
    "error" : logging.ERROR,
    "critical" : logging.CRITICAL
}

def __get_logger(level):
    __logger = logging.getLogger('logger')
    formatter = logging.Formatter(
        '%(levelname)s#%(asctime)s#%(message)s >> @file::%(filename)s@line::%(lineno)s')
    stream_handler = logging.StreamHandler()
    stream_handler.setFormatter(formatter)
    __logger.addHandler(stream_handler)
    __logger.setLevel(_level[level])
    return __logger


sentry_logging = LoggingIntegration(
    level=logging.WARNING,         # Capture ''
    event_level=logging.WARNING    # Send '' as events
)

sentry_sdk.init(
    "https://cab0e29e0c3a426f934e07932ab50e17@o911659.ingest.sentry.io/5848027",
    # Set traces_sample_rate to 1.0 to capture 100%
    # of transactions for performance monitoring.
    # We recommend adjusting this value in production.
    traces_sample_rate=1.0,
    integrations=[sentry_logging]
    # Bottle : https://docs.sentry.io/platforms/python/guides/bottle/performance/
    # dsn="https://examplePublicKey@o0.ingest.sentry.io/0",
    # traces_sample_rate=0.2,
    # traces_sampler=traces_sampler
)

def getUUID():
    return str(uuid.uuid4())

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
    try:
        _CREDENTIAL_SUBJECTS[uuid] = credentialSubject
        return True
    except Exception:
        return False

def getCredentialSubject(uuid):
    try:
        credentialSubject = _CREDENTIAL_SUBJECTS[uuid]
        return credentialSubject
    except Exception:
        return None

def makeJWS(vc, privateKey):
    try :
        headerJSON = {"alg":"RS256","b64":False,"crit":["b64"]}
        header_base64 = base64.urlsafe_b64encode(json.dumps(headerJSON).encode('utf8'))
        header_ = header_base64.decode('utf8').rstrip("=")
        vcString = json.dumps(vc)
        sig_decoded = signString(vcString, privateKey)
        sig_base64 = base64.urlsafe_b64encode(base58.b58decode(sig_decoded))
        sig_ = sig_base64.decode('utf8').rstrip("=")
        return header_ + ".." + sig_
    except Exception:
        return None

def getVerifiedJWT(request, secret):
    try :
        encoded_jwt = request.headers.get('Authorization')
        encoded_jwt = encoded_jwt.split(" ")[1] # FROM Bearer
        decoded_jwt = jwt.decode(encoded_jwt, secret, algorithms=["HS256"])
        return decoded_jwt
    except Exception:
        return None

def getPubkeyFromDIDDocument(did):
    try:
        did_req = requests.get(SAMPLE['platform']['urls']['document']+"?did="+did) 
        pubkey = json.loads(json.loads(did_req.text)['data'])['verificationMethod'][0]['publicKeyBase58']
    except Exception:
        pubkey = SAMPLE['holder']['publicKey']
    return pubkey

def getVCScheme(scheme):
    return _VCSCHEME[scheme]