import os, hashlib, hmac, base64, time

times = int(time.time())


def getSHA256Sum(*args):
    instance = hashlib.sha256()
    for arg in args:
        if isinstance(arg, str):
            arg = arg.encode()
        instance.update(arg)
    return instance.digest()
def get_issued_at() -> bytes:
    return base64.b64encode(
        f"iat: {int(time.time()) * 60}\n".encode("utf-8")) + b"."
def get_issued_at_lite(mid: str,times) -> bytes:
    return base64.b64encode(
        f"issuedTo: {mid}\niat: {times}\n".encode("utf-8")) + b"." + base64.b64encode("type: YWT\nalg: HMAC_SHA1\n".encode("utf-8"))


def get_digest(key: bytes, iat: bytes) -> bytes:
    return base64.b64encode(hmac.new(key, iat, hashlib.sha1).digest())

def create_token(auth_key: str) -> str:
    mid, key = auth_key.partition(":")[::2]
    key = base64.b64decode(key.encode("utf-8"))
    iat = get_issued_at()
    digest = get_digest(key, iat).decode("utf-8")
    iat = iat.decode("utf-8")
    return mid + ":" + iat + "." + digest

auth = " autah key"
for t in auth.split("\n"):
	if t:
		print(create_token(t))
