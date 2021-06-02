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
import time
from multiprocessing import Process
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs

#if len(sys.argv[1:]) < 1:
#    sys.exit("[도전자] 도전받는자의 DID가 필요함)
#challengee_did = str(sys.argv[1:][0])

challengee_did = "did:mtm:Exgfmw6A5RLWWeJX2G4czjLJb8yDxM"

pattern = re.compile("^did:mtm:[a-km-zA-HJ-NP-Z1-9]{30,30}$")
if not pattern.match(challengee_did):
    sys.exit("Invalid DID provided")
universal_resolver_addr = "https://did-resolver.mitum.com/ddo/" # universal resolver를 사용하는 경우
print("[도전자] 도전 받는자의 DID: %s" % challengee_did)


# 사인 검증
def verify(challenge, sig, pubkey):
    verifying_key = ed25519.VerifyingKey(base64.b64encode(base58.b58decode(pubkey)),
                                         encoding="base64")
    verifying_key.verify(json.loads(sig)["payload"],
                         challenge.encode("ascii"),
                         encoding="hex")


# 콜백을 위한...
class MyHttpHandler(BaseHTTPRequestHandler):

    challenge = ""
    pubkey = ""
    callback_id = ""

    def do_POST(self):
        self.send_response(200)
        self.send_header('Content-type', 'application/json')
        self.end_headers()
        if callback_id != self.path.split("?")[1]:
            self.wfile.write(b"Unknown callback handle")
            sys.exit("[도전자] Unknown callback handle")
        try:
            content_len = int(self.headers.get('content-length', 0))
            post_body = self.rfile.read(content_len)
            print("[도전자][Callback] 도전받는자의 페이로드(사인) : %s " % json.loads(post_body)["payload"] )
            verify(challenge, post_body, pubkey)
            # Send the html message
            self.wfile.write(b"Valid sig")
            sys.exit("[도전자][Callback] 도전받는자의 DID %s 가 정상!!" % challengee_did)
        except Exception:
            self.wfile.write(b"Invalid sig")
            sys.exit("[도전자][Callback] 도전받는자의 DID %s 가 비정상!!" % challengee_did)
        return

    def log_message(self, format, *args):
        return


def callback_http(s):
    s.serve_forever()

# challenge generation function
def id_generator(size=32, chars=string.ascii_uppercase + string.digits):
    return ''.join(random.choice(chars) for _ in range(size))

challenge = id_generator()
print("[도전자] 랜덤 생성한 챌린지 컨텐츠 : %s" % challenge)

try:
    # get DID document - Universal resolver를 사용하는 경우
    #did_req = requests.get(universal_resolver_addr + challengee_did) 
    json_did_doc = {
        "@context": ["https://w3id.org/did/v1"],
        "id": "did:mtm:Exgfmw6A5RLWWeJX2G4czjLJb8yDxM",
        "service": [{
            "type": "DidAuthService",
            "serviceEndpoint": "http://127.0.0.1:3333"
        }],
        "authentication": [{
            "type": "Ed25519SignatureAuthentication2018",
            "publicKey": "did:mtm:Exgfmw6A5RLWWeJX2G4czjLJb8yDxM#key-1"
        }],
        "publicKey": [{
            "id": "did:mtm:Exgfmw6A5RLWWeJX2G4czjLJb8yDxM#key-1",
            "type": "Ed25519VerificationKey2018",
            "owner": "did:mtm:Exgfmw6A5RLWWeJX2G4czjLJb8yDxM",
            "publicKeyBase58": "3ofzDb2umnCy96yLwTHawjTCfPZNxPiaX3g9SjN9CwGV"
        }]
    }

    # did-document 파싱 (universal resolver로 가져온 경우)
    #json_did_doc = json.dumps(did_document)
    endpoint = [x for x in json_did_doc["service"] if x["type"] == "DidAuthService"][0]["serviceEndpoint"]
    print("[도전자][document] 도전받는자의 서비스 엔드포인트 : %s" % endpoint)
    pubKey_identifier = [x for x in json_did_doc["authentication"]][0]["publicKey"]
    pubkey = [x for x in json_did_doc["publicKey"] if x["id"] == pubKey_identifier][0]["publicKeyBase58"]
    print("[도전자][document] 도전받는자의 공개키 : %s" % pubkey)
    # 콜백 핸들용 랜덤 주소 생성
    callback_id = id_generator()
    challenge_data = {"payload": challenge, "callback": "http://127.0.0.1:4444/callback?" + callback_id}

    session = requests.session()
    challengee_addr = endpoint + "/.identity/challenge"

    print("")
    MyHttpHandler.pubkey = pubkey
    MyHttpHandler.challenge = challenge
    MyHttpHandler.callback_id = callback_id
    server = HTTPServer(('', 4444), MyHttpHandler)

    # 콜백용 프로세스 실행
    p = Process(target=callback_http, args=(server,))
    p.start()

    # 챌린지 보내기
    print("[도전자] 내 페이로드 : %s" % challenge_data)
    print("[도전자] 도전 받는 사람 주소 : %s" % challengee_addr)
    session.post(challengee_addr,data=json.dumps(challenge_data))
    
except Exception as ex:
    sys.exit("[도전자] Problems retrieving / validating / working with challengee's DID: %s" % str(ex))

time.sleep(2)
p.terminate()
