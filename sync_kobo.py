"""Synchronise Kobo -> summary.json (public) + data.enc.json (chiffré avec le code d'accès)."""
import os, json, base64, re, unicodedata, datetime, urllib.request
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

IT = 300000
slug = lambda t: re.sub(r"[^a-z0-9]+", "_", unicodedata.normalize("NFKD", str(t)).encode("ascii", "ignore").decode().lower()).strip("_")

def encrypt(data: bytes, code: str) -> dict:
    salt, iv = os.urandom(16), os.urandom(12)
    key = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=IT).derive(code.encode())
    b = lambda x: base64.b64encode(x).decode()
    return {"it": IT, "salt": b(salt), "iv": b(iv), "ct": b(AESGCM(key).encrypt(iv, data, None))}

def summarize(rows):
    p = {}
    for r in rows:
        r = {k.split("/")[-1]: v for k, v in r.items()}
        prov, z, d = slug(r.get("province", "")), str(r.get("zone_sante", "")), str(r.get("date_rapport", ""))[:10]
        if not (prov and z.strip() and re.match(r"\d{4}-\d{2}-\d{2}", d)): continue
        for tok in z.split():  # zone_sante peut contenir plusieurs zones (select_multiple)
            zs = slug(tok)
            if zs.startswith(prov + "_"): zs = zs[len(prov) + 1:]
            p.setdefault(prov, {}).setdefault(d, set()).add(zs)
    return {"upd": datetime.datetime.utcnow().isoformat(timespec="seconds"),
            "p": {k: {d: sorted(v) for d, v in o.items()} for k, o in p.items()}}

def fetch_all():
    server = os.environ.get("KOBO_SERVER", "https://kf.kobotoolbox.org")
    url = f"{server}/api/v2/assets/{os.environ['KOBO_UID']}/data/?format=json&limit=1000"
    rows = []
    while url:
        req = urllib.request.Request(url, headers={"Authorization": "Token " + os.environ["KOBO_TOKEN"]})
        j = json.load(urllib.request.urlopen(req, timeout=60))
        rows += j["results"]; url = j.get("next")
    return rows

if __name__ == "__main__":
    rows = fetch_all()
    json.dump(summarize(rows), open("summary.json", "w", encoding="utf8"), ensure_ascii=False)
    json.dump(encrypt(json.dumps(rows, ensure_ascii=False).encode(), os.environ["ACCESS_CODE"]), open("data.enc.json", "w"))
    print(len(rows), "rapports synchronisés")
