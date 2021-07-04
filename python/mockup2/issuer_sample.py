# -*- coding: utf-8 -*-
import json
import bottle
import canister
from bottle import response, request, HTTPResponse
import jwt
from tools import did as DID
from tools import log as DIDLOG

LOG = DIDLOG.__get_logger('warning')
LOGI = LOG.info
LOGD = LOG.debug
LOGW = LOG.warning

issuer_port = 3333
app = bottle.Bottle()
app.install(canister.Canister())

_ISSUER_DID = DID.SAMPLE['issuer']['did']
_ISSUER_PRIVATEKEY = DID.SAMPLE['issuer']['privateKey']
_ISSUER_SECRET = DID.SAMPLE['issuer']['secret']
_ISSUER_URL = DID.SAMPLE['issuer']['url']
_PLATFORM_SCHEME_URL = DID.SAMPLE['platform']['urls']['scheme']
_PLATFORM_RESOLVER_URL = DID.SAMPLE['platform']['urls']['resolver']

@app.get('/VCScheme')
def VCScheme():
    try:
        scheme = request.query['scheme']
        schemeID = DID.getVCScheme(scheme)
        schemeJSON = json.dumps(
            {
                "scheme": _PLATFORM_SCHEME_URL+"?id="+schemeID,
                "VCPost": _ISSUER_URL+"/VC",
                "VCGet" : _ISSUER_URL+"/VC"
            })
    except Exception:
        response.status = 404
        return "Error"
    LOGW("[Issuer] VC Scheme 위치 알려주기 : %s" % (schemeJSON))
    raise HTTPResponse(schemeJSON, status=200, headers={})

@app.post('/VC')
def VCPost():
    try:
        vc = json.loads(request.body.read())
        myUUID = DID.getUUID()
        did = vc['did']
        credentialSubject = vc['credentialSubject']
        DID.saveCredentialSubject(myUUID, credentialSubject)
        challenge = DID.generateChallenge()
        pubkey = DID.getPubkeyFromDIDDocument(did)
        encoded_jwt = jwt.encode({"uuid": myUUID, "pubkey":pubkey, "challenge":challenge}, _ISSUER_SECRET, algorithm="HS256")
        LOGW("[Issuer] DID AUTH - VC Post(%s) : 생성한 챌린지(%s), DID Document의 공개키(%s), Holder에게 JWT(%s) 발급." 
        % (credentialSubject, challenge, pubkey, encoded_jwt))
    except Exception:
        response.status = 404
        LOGW("[Issuer] DID AUTH - VC Post에서 Exception 발생")
        return "Error"
    raise HTTPResponse(json.dumps({"payload": challenge, "endPoint":_ISSUER_URL+"/response"}), status=202, headers={'Authorization':str(encoded_jwt.decode("utf-8"))})

@app.get('/response')
def response():
    try:
        get_body = request.query['signature']
    except Exception:
        response.status = 400
        return "Error"
    try:
        jwt = DID.getVerifiedJWT(request, _ISSUER_SECRET)
        challengeRet = DID.verifyString(jwt['challenge'] , get_body, jwt['pubkey'])
        if challengeRet == True:
            LOGW("[Issuer] DID AUTH - Verified : 사인 값(%s) 검증 성공. VC를 만들고, 사인된 VC 보내기" % get_body)
        else:
            LOGW("[Issuer] DID AUTH - Verify : 사인 값(%s) 검증 실패." % get_body)
    except Exception:
        challengeRet = False
        LOGW("[Issuer] DID AUTH - Verify : ERROR : 검증 실패" % jwt['challenge'])
    raise HTTPResponse(json.dumps({"Response": challengeRet}), status=202, headers={})

@app.get('/VC')
def VCGet():
    try:
        jwt = DID.getVerifiedJWT(request, _ISSUER_SECRET)
        myUUID = jwt['uuid']
        credentialSubject = DID.getCredentialSubject(myUUID)
        vc = DID.makeSampleVC(_ISSUER_DID, credentialSubject)
        jws = DID.makeJWS(vc, _ISSUER_PRIVATEKEY)
        vc['proof']["jws"] = jws
    except Exception:
        response.status = 404
        return "Error"
    LOGW("[Issuer] VC Issuance - %s" % vc)
    raise HTTPResponse(json.dumps({"Response":True, "VC": vc}), status=202, headers={})

if __name__ == "__main__":
    app.run(host='0.0.0.0', port=issuer_port)
