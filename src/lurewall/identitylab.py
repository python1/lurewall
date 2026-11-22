# SPDX-License-Identifier: AGPL-3.0-only
"""Offline identity rehearsals, with a fresh synthetic signer and a partial feed."""
import base64
import hashlib
import json
import secrets
import tempfile
import time
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from lurewall import agentfeeds, webbotauth
from lurewall.accesslog import Record, parse_line
from lurewall.agentidentity import Observer

SIGNER = "https://agent.example"
HOST = "origin.example"


def log_fields(now):
    return {
        "v":"4","ts":f"{now}.011","duration":"0.010","method":"GET","uri":"/",
        "request":"GET / HTTP/2.0","status":"200","ua":"GPTBot","ip":"192.0.2.8",
        "lang":"","referer":"","sec_fetch_site":"","request_id":secrets.token_hex(16),
        "forwarded_for":"","scheme":"https","authority":HOST,"ingress":HOST,
        "protocol":"HTTP/2.0","signature":"","signature_input":"","signature_agent":"",
    }


def sign_fields(fields,now,key,kid):
    label = "lab"
    components = '("@authority" "signature-agent";key="lab")'
    params = f'{components};created={now};expires={now+180};keyid="{kid}";tag="web-bot-auth"'
    base = (f'"@authority": {HOST}\n"signature-agent";key="lab": "{SIGNER}"\n'
            f'"@signature-params": {params}').encode()
    fields.update(ua="browser",signature_agent=f'{label}="{SIGNER}"',
                  signature_input=label+"="+params,
                  signature=label+"=:"+base64.b64encode(key.sign(base)).decode()+":")


def fixture(root,now):
    pins = root/"pins"
    pins.mkdir()
    key = Ed25519PrivateKey.generate()
    kid = secrets.token_hex(8)
    raw = json.dumps({"keys":[{"kty":"OKP","crv":"Ed25519","kid":kid,
                               "x":base64.urlsafe_b64encode(key.public_key().public_bytes_raw()).decode().rstrip("=")}]}).encode()
    ranges = b'{"prefixes":[{"ipv4Prefix":"198.51.100.0/24"}]}'
    (pins/"lab.json").write_bytes(raw)
    (pins/"ranges.json").write_bytes(ranges)
    config = root/"agents.toml"
    config.write_text(f'''visible_authorities = ["{HOST}"]
[feed.lab]
url = "{SIGNER}/.well-known/http-message-signatures-directory"
signer = "{SIGNER}"
sha256 = "{hashlib.sha256(raw).hexdigest()}"
pin_until = {now+3600}
[feed.ranges]
url = "https://ranges.example/ranges.json"
coverage = "partial"
sha256 = "{hashlib.sha256(ranges).hexdigest()}"
pin_until = {now+3600}
[claim.GPTBot]
ranges = "ranges"
''')
    replay = root/"replay.sqlite"
    webbotauth.initialize(replay)
    observer = Observer(config,agentfeeds.settings(config),root,root,replay)
    return observer,key,kid


def observe(observer,fields,now):
    parsed = parse_line(json.dumps(fields).encode(),0,now_ms=now*1000,max_age_ms=60000)
    if not isinstance(parsed,Record):
        raise ValueError("lab capture did not parse")
    return observer.observe(parsed,now*1000)


def run():
    now = int(time.time())
    with tempfile.TemporaryDirectory() as temp:
        observer,key,kid = fixture(Path(temp),now)
        fields = log_fields(now)
        cases = [("Spoofed GPTBot",observe(observer,fields,now),"indeterminate","partial_miss")]
        sign_fields(fields,now,key,kid)
        cases.append(("Offline signer",observe(observer,fields,now),"verified","signature"))
        fields["request_id"] = secrets.token_hex(16)
        cases.append(("Replay",observe(observer,fields,now),"indeterminate","replay"))
    for name,result,_,_ in cases:
        print(f"{name}: {result['verdict']} ({result['reason']})")
    return int(any((r["verdict"],r["reason"],r["counted"])!=(v,why,False) for _,r,v,why in cases))

