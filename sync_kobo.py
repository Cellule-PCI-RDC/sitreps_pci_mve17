"""Synchronise Kobo -> summary.json (public) + data.enc.json (chiffré avec le code d'accès)."""
import os, json, base64, re, unicodedata, datetime, hashlib, urllib.request
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

IT = 300000
def slug(t):
    # identique à la fonction sl() de index.html (accents retirés, tout le reste devient « _ »)
    t = "".join(c for c in unicodedata.normalize("NFD", str(t)) if unicodedata.category(c) != "Mn").lower()
    return re.sub(r"[^a-z0-9]+", "_", t).strip("_")

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


# ---------- 2ème base : évaluations PCI des ESS (indicateurs de la diapo 2) ----------
ESS_FIELDS = {"province": "Province", "zs": "Zone de santé", "aire": "Aire de santé",
              "nom": "Nom de l'établissement de santé", "autre": "Ecrivez le nom de l'établissement de santé",
              "date": "Date d'évaluation (JJ/MM/AAAA)"}
ESS_SCORE = "score_pct"

def _labels(x):
    if isinstance(x, str): return [x]
    if isinstance(x, list): return [str(i) for i in x if i]
    if isinstance(x, dict): return [str(i) for i in x.values() if i]
    return []

def build_ess(recs):
    """recs: dicts {p,z,a,n,d,s}. Retourne {province: [ [ [date, score], ... ] par établissement ]}."""
    ev = {}
    for r in recs:
        ev.setdefault((r["p"], slug(r["z"]), slug(r["a"]), slug(r["n"])), []).append((r["d"], r["s"]))
    out = {}
    for (p, *_), v in ev.items():
        v.sort()
        out.setdefault(p, []).append([[d, s] for d, s in v])
    return out

def getv(row, name):
    """Valeur d'un champ, même s'il est rangé dans un groupe (clé « groupe/champ »)."""
    if name in row: return row[name]
    for kk, x in row.items():
        if kk.split("/")[-1] == name: return x
    return ""

def ess_records(asset, rows):
    survey = asset["content"]["survey"]
    choices = {}
    for c in asset["content"].get("choices", []):
        lb = _labels(c.get("label"))
        if lb: choices[(c.get("list_name"), c.get("name"))] = lb[0]
    want = {k: slug(v) for k, v in ESS_FIELDS.items()}
    item = {}
    for q in survey:
        for lb in _labels(q.get("label")):
            for k, w in want.items():
                if slug(lb) == w and k not in item: item[k] = q
    missing = [ESS_FIELDS[k] for k in want if k not in item and k != "autre"]
    if missing: raise RuntimeError("Champs introuvables dans la base ESS : " + ", ".join(missing))
    print("Champs ESS reconnus :", {k: q["name"] for k, q in item.items()})
    def raw(row, k):
        q = item.get(k)
        if not q: return ""
        for key in (q.get("$xpath"), q["name"]):
            if key and key in row: return str(row[key] or "").strip()
        return str(getv(row, q["name"]) or "").strip()
    def label(row, k):
        v = raw(row, k); t = str(item.get(k, {}).get("type", "")).split()
        return choices.get((t[1], v), v) if t and t[0] == "select_one" and len(t) > 1 else v
    recs, no_score = [], 0
    for row in rows:
        try: s = float(str(getv(row, ESS_SCORE)).replace(",", "."))
        except ValueError: no_score += 1; continue
        d = raw(row, "date")[:10]; sub = str(row.get("_submission_time", ""))[:10]
        if not re.match(r"\d{4}-\d{2}-\d{2}", d): d = sub
        if re.match(r"\d{4}-\d{2}-\d{2}", sub) and sub < d: d = sub   # une évaluation ne peut pas être postérieure à sa saisie
        nom = raw(row, "nom")
        if slug(label(row, "nom")) == "autre" and raw(row, "autre"): nom = raw(row, "autre")
        p = slug(label(row, "province"))
        if p and nom and d: recs.append({"p": p, "z": raw(row, "zs"), "a": raw(row, "aire"), "n": nom, "d": d, "s": s})
    print(f"Base ESS : {len(rows)} lignes, {len(recs)} évaluations exploitables, {no_score} sans score")
    if rows and not recs: raise RuntimeError("aucune évaluation exploitable (champ score_pct introuvable ?)")
    return recs

def fetch_json(url):
    req = urllib.request.Request(url, headers={"Authorization": "Token " + os.environ["KOBO_TOKEN"]})
    return json.load(urllib.request.urlopen(req, timeout=120))

def fetch_ess():
    server = os.environ.get("KOBO_SERVER", "https://kf.kobotoolbox.org"); uid = os.environ["KOBO_UID_ESS"]
    asset = fetch_json(f"{server}/api/v2/assets/{uid}/?format=json")
    rows, url = [], f"{server}/api/v2/assets/{uid}/data/?format=json&limit=1000"
    while url:
        j = fetch_json(url); rows += j["results"]; url = j.get("next")
    return build_ess(ess_records(asset, rows))

if __name__ == "__main__":
    rows = fetch_all()
    ess = None
    if os.environ.get("KOBO_UID_ESS"):
        try:
            ess = fetch_ess()
        except Exception as e:  # la base ESS ne doit pas bloquer la synchronisation principale
            print("ATTENTION base ESS non synchronisée :", e)
    dh = hashlib.sha256((json.dumps(rows, sort_keys=True, ensure_ascii=False) + json.dumps(ess, sort_keys=True)).encode()).hexdigest()
    try:
        old = json.load(open("summary.json", encoding="utf8")).get("dh")
    except Exception:
        old = None
    if old == dh:
        print("Aucun changement : rien à publier")
        raise SystemExit
    summ = summarize(rows); summ["dh"] = dh
    if ess is not None: summ["ess"] = ess
    json.dump(summ, open("summary.json", "w", encoding="utf8"), ensure_ascii=False, separators=(",", ":"))
    json.dump(encrypt(json.dumps(rows, ensure_ascii=False).encode(), os.environ["ACCESS_CODE"]), open("data.enc.json", "w"))
    print(len(rows), "rapports synchronisés" + (f", {sum(len(v) for v in ess.values())} ESS évalués" if ess else ""))
