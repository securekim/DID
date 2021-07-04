# -*- coding: utf-8 -*-
import json
import bottle
import canister
from bottle import response, request, HTTPResponse
import jwt
import did_tool as DID

LOG = DID.__get_logger('debug')
LOGI = LOG.info
LOGD = LOG.debug

issuer_port = 3333
app = bottle.Bottle()
app.install(canister.Canister())

_ISSUER_DID = DID.SAMPLE['issuer']['did']
_ISSUER_PRIVATEKEY = DID.SAMPLE['issuer']['privateKey']
_ISSUER_SECRET = DID.SAMPLE['issuer']['secret']
_ISSUER_URL = DID.SAMPLE['issuer']['url']
universal_resolver_addr = "https://did-resolver.mitum.com/ddo/" 

@app.get('/VCScheme')
def VCScheme():
    try:
        scheme = request.query['scheme']
        schemeID = DID.getVCScheme(scheme)
        schemeJSON = json.dumps(
            {
                "scheme": "http://49.50.164.195:8080/v1/scheme?id="+schemeID,
                "VCPost": _ISSUER_URL+"/VC",
                "VCGet" : _ISSUER_URL+"/VC"
            })
    except Exception:
        response.status = 404
        return "Error"
    LOGD("[이슈어] VC Scheme 위치 알려주기 : %s" % (schemeJSON))
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
        LOGD("[이슈어] 랜덤 생성한 챌린지 컨텐츠 : %s" % challenge)
        pubkey = DID.getPubkeyFromDIDDocument(did)
        LOGD("[이슈어][document] 모바일의 공개키 : %s" % pubkey)
        encoded_jwt = jwt.encode({"uuid": myUUID, "pubkey":pubkey, "challenge":challenge}, _ISSUER_SECRET, algorithm="HS256")
        LOGD("[이슈어] 모바일 헤더에 JWT 발급 : %s" % (encoded_jwt))
    except Exception:
        response.status = 404
        return "Error"
    LOGD("[이슈어] 모바일의 VC 요청 : %s" % (credentialSubject))
    raise HTTPResponse(json.dumps({"payload": challenge, "endPoint":_ISSUER_URL+"/response"}), status=202, headers={'Authorization':str(encoded_jwt.decode("utf-8"))})

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
    LOGD("[이슈어] 최종 발급된 VC : %s" % vc)
    raise HTTPResponse(json.dumps({"Response":True, "VC": vc}), status=202, headers={})

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
        LOGD("[이슈어] 받은 사인 값 : %s" % get_body)
        if challengeRet == True:
            LOGD("[이슈어] VC를 만들고, 사인된 VC 보내기")
    except Exception:
        challengeRet = False
    LOGD("[이슈어] 검증 결과 : %s" % challengeRet)
    raise HTTPResponse(json.dumps({"Response": challengeRet}), status=202, headers={})

if __name__ == "__main__":
    app.run(host='0.0.0.0', port=issuer_port)
