# Motore dell'app Anti-Hack (nessuna interfaccia): hash, controlli, database ClamAV, VirusTotal
import hashlib, json, os, shutil, sqlite3, ssl, tarfile, time, uuid
import urllib.request, urllib.error

try:
    import certifi
    CTX = ssl.create_default_context(cafile=certifi.where())
except Exception:
    CTX = None

VT = os.environ.get("ANTIHACK_VT", "https://www.virustotal.com/api/v3")
CVD_BASE = os.environ.get("ANTIHACK_CVD_BASE", "https://database.clamav.net")
CVD_FILES = ["main.cvd", "daily.cvd"]
UA = {"User-Agent": "ClamAV/1.0.0 (OS: linux-gnu, ARCH: x86_64, CPU: x86_64)"}
EICAR = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"
MAX_UPLOAD = 200 * 1024 * 1024

DATA = DBF = CONF = None
KEY = ""

DANGER = {".apk", ".exe", ".bat", ".cmd", ".scr", ".vbs", ".jar", ".sh", ".msi", ".js", ".dex", ".so"}
MEDIA = {".jpg", ".jpeg", ".png", ".gif", ".pdf", ".mp3", ".mp4", ".txt", ".doc", ".docx", ".xls", ".xlsx"}
RULES = [
    ("send_sms", 15, "puo' inviare SMS"), ("read_sms", 15, "puo' leggere i tuoi SMS"),
    ("bind_device_admin", 25, "chiede permessi di amministratore"),
    ("request_install_packages", 10, "puo' installare altre app"),
    ("system_alert_window", 10, "puo' mostrare finestre sopra altre app"),
    ("accessibilityservice", 10, "usa accessibilita' (spesso abusata)"),
    ("dexclassloader", 15, "carica codice nascosto"),
    ("runtime.getruntime().exec", 10, "esegue comandi di sistema"),
    ("su -c", 20, "tenta di ottenere root"), ("chmod 777", 15, "cambia permessi in modo pericoloso"),
    ("/system/bin/sh", 10, "apre una shell"), ("powershell -enc", 30, "comando nascosto codificato"),
    ("nc -e", 30, "reverse shell"), ("keylog", 25, "possibile keylogger"),
    ("wget http", 10, "scarica file da internet"), ("curl http", 10, "scarica file da internet"),
]


def init(data_dir):
    global DATA, DBF, CONF, KEY
    DATA = data_dir
    os.makedirs(DATA, exist_ok=True)
    DBF = os.path.join(DATA, "firme.db")
    CONF = os.path.join(DATA, ".vtkey")
    try:
        with open(CONF) as f:
            KEY = f.read().strip()
    except Exception:
        KEY = ""


def has_key():
    return bool(KEY)


def _save_key(k):
    global KEY
    KEY = k
    with open(CONF, "w") as f:
        f.write(k)


# ---------- controllo sul telefono ----------
def real_type(h):
    if h.startswith(b"\x7fELF"): return "elf"
    if h.startswith(b"MZ"): return "exe"
    if h.startswith(b"PK\x03\x04"): return "zip"
    if h.startswith(b"\x89PNG"): return "png"
    if h[:2] == b"\xff\xd8": return "jpg"
    if h.startswith(b"%PDF"): return "pdf"
    if h.startswith(b"GIF"): return "gif"
    if h.startswith(b"dex"): return "dex"
    if h.startswith(b"#!"): return "script"
    return ""


def analyze_local(path, name):
    n = name.lower()
    ext = os.path.splitext(n)[1]
    score, why = 0, []
    if ext in DANGER:
        score += 20
        why.append("file eseguibile/installabile (%s)" % ext)
    for m in MEDIA:
        for d in DANGER:
            if n.endswith(m + d):
                score += 40
                why.append("doppia estensione ingannevole (%s)" % (m + d))
    with open(path, "rb") as f:
        head = f.read(16)
    t = real_type(head)
    if ext in MEDIA and t in ("elf", "exe", "dex", "script"):
        score += 70
        why.append("finto %s: in realta' e' un programma (%s)" % (ext, t))
    if ext == ".apk" and t != "zip":
        score += 30
        why.append("APK con struttura anomala")
    size = os.path.getsize(path)
    if 0 < size < 5 * 1024 * 1024:
        with open(path, "rb") as f:
            data = f.read().lower()
        for pat, pts, msg in RULES:
            if pat.encode() in data:
                score += pts
                why.append(msg)
    score = min(score, 100)
    return {"score": score, "level": 0 if score < 20 else (1 if score < 50 else 2), "reasons": why}


def hash_file(path):
    m, s = hashlib.md5(), hashlib.sha256()
    size = 0
    with open(path, "rb") as f:
        while True:
            b = f.read(1 << 20)
            if not b:
                break
            m.update(b)
            s.update(b)
            size += len(b)
    return m.hexdigest(), s.hexdigest(), size


# ---------- database ClamAV ----------
def db_info():
    try:
        c = sqlite3.connect(DBF)
        m = dict(c.execute("SELECT k,v FROM meta").fetchall())
        c.close()
        return int(m.get("count", 0)), m.get("updated", "")
    except Exception:
        return 0, ""


def db_check(md5, sha, size):
    try:
        c = sqlite3.connect(DBF)
        if c.execute("SELECT 1 FROM fp WHERE hash IN (?,?)", (md5, sha)).fetchone():
            c.close()
            return None
        rows = c.execute("SELECT name,size FROM sigs WHERE hash IN (?,?)", (md5, sha)).fetchall()
        c.close()
        for name, sz in rows:
            if sz == -1 or sz == size:
                return name
    except Exception:
        pass
    return None


def cvd_entries(path):
    with open(path, "rb") as f:
        if not f.read(512).startswith(b"ClamAV-VDB"):
            raise ValueError("file database non valido")
        tf = tarfile.open(fileobj=f, mode="r|gz")
        for m in tf:
            if not m.isfile():
                continue
            n = m.name.lower()
            is_sig = n.endswith((".hdb", ".hsb", ".hdu", ".hsu"))
            is_fp = n.endswith((".fp", ".sfp"))
            if not (is_sig or is_fp):
                continue
            for raw in tf.extractfile(m):
                p = raw.decode("utf-8", "ignore").strip().split(":")
                if len(p[0]) not in (32, 64):
                    continue
                h = p[0].lower()
                if is_fp:
                    yield "fp", h, 0, ""
                elif len(p) >= 3:
                    try:
                        size = -1 if p[1] == "*" else int(p[1])
                    except ValueError:
                        continue
                    yield "sig", h, size, p[2]


def _download(url, dest, label, progress):
    req = urllib.request.Request(url, headers=UA)
    last = 0
    with urllib.request.urlopen(req, timeout=60, context=CTX) as resp, open(dest, "wb") as out:
        total = int(resp.headers.get("Content-Length") or 0)
        got = 0
        while True:
            b = resp.read(1 << 20)
            if not b:
                break
            out.write(b)
            got += len(b)
            if time.time() - last > 0.5:
                last = time.time()
                progress("Scarico %s: %d MB%s" % (label, got >> 20, (" di %d MB" % (total >> 20)) if total else ""))


def update_db(progress=lambda m: None):
    """Scarica e costruisce il database. Solleva un'eccezione se qualcosa va storto."""
    newf = DBF + ".new"
    if os.path.exists(newf):
        os.remove(newf)
    try:
        c = sqlite3.connect(newf)
        c.execute("CREATE TABLE sigs(hash TEXT PRIMARY KEY, size INTEGER, name TEXT) WITHOUT ROWID")
        c.execute("CREATE TABLE fp(hash TEXT PRIMARY KEY) WITHOUT ROWID")
        c.execute("CREATE TABLE meta(k TEXT PRIMARY KEY, v TEXT)")
        done = 0
        for fn in CVD_FILES:
            tmpf = os.path.join(DATA, fn)
            _download(CVD_BASE + "/" + fn, tmpf, fn, progress)
            progress("Leggo le firme di %s..." % fn)
            sigs, fps = [], []
            for kind, h, size, name in cvd_entries(tmpf):
                if kind == "sig":
                    sigs.append((h, size, name))
                else:
                    fps.append((h,))
                if len(sigs) >= 20000:
                    c.executemany("INSERT OR REPLACE INTO sigs VALUES (?,?,?)", sigs)
                    done += len(sigs)
                    sigs = []
                    progress("Leggo le firme di %s: %d salvate..." % (fn, done))
            if sigs:
                c.executemany("INSERT OR REPLACE INTO sigs VALUES (?,?,?)", sigs)
            if fps:
                c.executemany("INSERT OR REPLACE INTO fp VALUES (?)", fps)
            c.commit()
            os.remove(tmpf)
        total = c.execute("SELECT COUNT(*) FROM sigs").fetchone()[0]
        c.execute("INSERT INTO meta VALUES ('count', ?)", (str(total),))
        c.execute("INSERT INTO meta VALUES ('updated', ?)", (time.strftime("%d/%m/%Y"),))
        c.commit()
        c.close()
        os.replace(newf, DBF)
        return total
    except Exception:
        try:
            os.remove(newf)
        except Exception:
            pass
        raise


# ---------- VirusTotal ----------
def _req(method, url, data=None, headers=None, key=None, timeout=120):
    h = {"x-apikey": KEY if key is None else key}
    if headers:
        h.update(headers)
    r = urllib.request.Request(url, data=data, headers=h, method=method)
    try:
        with urllib.request.urlopen(r, timeout=timeout, context=CTX) as resp:
            return resp.status, json.loads(resp.read().decode())
    except urllib.error.HTTPError as e:
        try:
            return e.code, json.loads(e.read().decode())
        except Exception:
            return e.code, {}
    except Exception:
        return 0, {}


def _flagged(results):
    return [[n, r.get("result") or r.get("category")] for n, r in results.items()
            if r.get("category") in ("malicious", "suspicious")]


def vt_lookup(sha):
    if not KEY:
        return {"status": "nokey"}
    code, js = _req("GET", VT + "/files/" + sha)
    if code == 200:
        a = js["data"]["attributes"]
        return {"status": "found", "stats": a["last_analysis_stats"],
                "flagged": _flagged(a.get("last_analysis_results", {}))}
    return {"status": {404: "unknown", 401: "badkey", 403: "badkey", 429: "limit", 0: "offline"}.get(code, "error")}


def validate_key(k):
    """Ritorna (stato, antivirus_che_vedono_EICAR)."""
    code, js = _req("GET", VT + "/files/" + EICAR, key=k)
    if code in (401, 403):
        return "badkey", 0
    _save_key(k)
    if code == 200:
        return "ok", js["data"]["attributes"]["last_analysis_stats"].get("malicious", 0)
    return {429: "limit", 0: "offline"}.get(code, "error"), 0


def vt_upload(path, name):
    """Ritorna (id_analisi, messaggio_errore)."""
    if os.path.getsize(path) > MAX_UPLOAD:
        return None, "Il file supera 200 MB: non posso caricarlo."
    url = VT + "/files"
    if os.path.getsize(path) > 32 * 1024 * 1024:
        code, js = _req("GET", VT + "/files/upload_url")
        if code != 200:
            return None, "Errore (%s) nel preparare il caricamento." % code
        url = js["data"]
    b = uuid.uuid4().hex
    fn = name.replace('"', "").replace("\r", "").replace("\n", "")
    head = (('--%s\r\nContent-Disposition: form-data; name="file"; filename="%s"\r\n'
             'Content-Type: application/octet-stream\r\n\r\n') % (b, fn)).encode("utf-8")
    tail = ("\r\n--%s--\r\n" % b).encode()
    mp = path + ".mp"
    with open(mp, "wb") as out:
        out.write(head)
        with open(path, "rb") as src:
            shutil.copyfileobj(src, out, 1 << 20)
        out.write(tail)
    try:
        with open(mp, "rb") as f:
            code, js = _req("POST", url, f, {"Content-Type": "multipart/form-data; boundary=" + b,
                                             "Content-Length": str(os.path.getsize(mp))}, timeout=600)
    finally:
        try:
            os.remove(mp)
        except Exception:
            pass
    if code == 200:
        return js["data"]["id"], ""
    if code == 429:
        return None, "Limite gratuito raggiunto. Riprova tra un minuto."
    return None, "Errore caricamento (%s). Controlla internet." % code


def vt_poll(aid):
    code, js = _req("GET", VT + "/analyses/" + aid)
    try:
        a = js["data"]["attributes"]
        if a.get("status") == "completed":
            return {"status": "completed", "stats": a["stats"], "flagged": _flagged(a.get("results", {}))}
        return {"status": a.get("status", "queued")}
    except Exception:
        return {"status": "error"}


# ---------- scansione completa ----------
def scan_file(path, name):
    md5, sha, size = hash_file(path)
    local = analyze_local(path, name)
    cnt, upd = db_info()
    if cnt > 0:
        hit = db_check(md5, sha, size)
        engine = {"status": "hit", "name": hit} if hit else {"status": "clean", "count": cnt, "date": upd}
    else:
        engine = {"status": "nodb"}
    return {"name": name, "sha256": sha, "local": local, "engine": engine, "vt": vt_lookup(sha)}
