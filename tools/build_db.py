#!/usr/bin/env python3
"""
Builds and signs the Sentinel Guard threat database bundle.

Sources (one free abuse.ch Auth-Key, from https://auth.abuse.ch/, in ABUSECH_AUTH_KEY):
  * MalwareBazaar: SHA-256 of Android (APK) samples, plus recent samples of all types
  * URLhaus: hosts currently serving malware

The bundle accumulates: each run merges new entries into the previously published
bundle (--previous DIR), so daily runs grow the database beyond the API's
1000-most-recent window. Hosts expire after --host-ttl-days without being seen.

Output (all in --out):
  threats.bin   sorted, deduplicated 32-byte SHA-256 records
  certs.bin     same format; signing-cert digests from tools/bad_certs.txt
  domains.txt   one host per line
  hosts_state.json  host -> last-seen (not loaded by the app; keeps TTL state)
  manifest.json + manifest.sig (ECDSA P-256 / SHA-256, base64 DER, made with openssl)

Usage:
  ABUSECH_AUTH_KEY=... python3 tools/build_db.py --key ~/keys/sentinelguard/threatdb-signing.pem --out out/db --previous site/db
  python3 tools/build_db.py --offline --key ... --out app/src/main/assets/threatdb   # sign local data only
"""
import argparse, base64, csv, datetime as dt, hashlib, io, json, os, re, subprocess, sys, time, urllib.parse, urllib.request, zipfile

SHA256 = re.compile(r"^[0-9a-f]{64}$")
HERE = os.path.dirname(os.path.abspath(__file__))
UA = "SentinelGuard-dbbuilder/1.0"


# File types that can hurt an Android phone (installers, dex/jar payloads, and the
# archive/document types droppers arrive in). Windows-only types are left out to keep
# the bundle around 3 MB instead of 37 MB.
ANDROID_TYPES = {"apk", "xapk", "apks", "apkm", "dex", "jar", "zip", "rar", "7z", "pdf"}
MB_FULL_EXPORT = "https://mb-api.abuse.ch/v2/files/exports/{key}/full.csv.zip"
URLHAUS_HOSTFILE = "https://urlhaus-api.abuse.ch/v2/files/exports/{key}/hostfile.txt"


def post(url, data, key):
    req = urllib.request.Request(url, data=urllib.parse.urlencode(data).encode(), method="POST")
    req.add_header("Auth-Key", key)
    req.add_header("User-Agent", UA)
    with urllib.request.urlopen(req, timeout=120) as r:
        return json.loads(r.read().decode())


def get(url, key=None):
    req = urllib.request.Request(url)
    req.add_header("User-Agent", UA)
    if key:
        req.add_header("Auth-Key", key)
    with urllib.request.urlopen(req, timeout=300) as r:
        return r.read()


def mb_hashes(key):
    out = set()
    # Android samples (the core of the app's detection)
    r = post("https://mb-api.abuse.ch/api/v1/", {"query": "get_file_type", "file_type": "apk", "limit": "1000"}, key)
    if r.get("query_status") == "ok":
        out |= {d["sha256_hash"].lower() for d in r.get("data", []) if SHA256.match(d.get("sha256_hash", "").lower())}
    else:
        print("MalwareBazaar apk query:", r.get("query_status"), file=sys.stderr)
    # Full dump (all history; abuse.ch allows ~4 downloads/day, we do one).
    export = os.environ.get("MB_EXPORT_URL") or MB_FULL_EXPORT
    out |= parse_export(get(export.replace("{key}", key), key))
    return out


def parse_export(blob):
    """Accepts a CSV or a ZIP containing one; keeps sha256 of rows whose file type is Android-relevant."""
    if blob[:2] == b"PK":
        z = zipfile.ZipFile(io.BytesIO(blob))
        blob = z.read(z.namelist()[0])
    found = set()
    for row in csv.reader(io.StringIO(blob.decode("utf-8", "replace"))):
        if not row or row[0].startswith("#"):
            continue
        cells = [c.strip().strip('"').strip().lower() for c in row]
        if len(cells) > 6 and cells[6] in ANDROID_TYPES:
            sha = next((c for c in cells if SHA256.match(c)), None)
            if sha:
                found.add(sha)
    return found


def urlhaus_hosts(key):
    hosts = set()
    # Hostfile: every host currently serving malware.
    for line in get(URLHAUS_HOSTFILE.format(key=key), key).decode("utf-8", "replace").splitlines():
        parts = line.split()
        if len(parts) == 2 and not line.startswith("#"):
            h = parts[1].lower().strip(".")
            if "." in h and not re.match(r"^\d+\.\d+\.\d+\.\d+$", h):
                hosts.add(h)
    # Plus the most recent submissions (catches hosts added since the hostfile was cut).
    r = json.loads(get("https://urlhaus-api.abuse.ch/v1/urls/recent/limit/1000/", key).decode())
    for u in r.get("urls", []):
        if u.get("url_status") not in (None, "online", "unknown"):
            continue
        h = (u.get("host") or urllib.parse.urlparse(u.get("url", "")).hostname or "").lower().strip(".")
        if h and not re.match(r"^\d+\.\d+\.\d+\.\d+$", h) and "." in h:
            hosts.add(h)
    return hosts


# Hosts that appear in URLhaus because malware was *hosted* there, but blocking the
# whole domain would flag huge numbers of legitimate links.
SHARED_HOSTING = {
    "github.com", "raw.githubusercontent.com", "objects.githubusercontent.com", "drive.google.com",
    "docs.google.com", "storage.googleapis.com", "dropbox.com", "www.dropbox.com", "dl.dropboxusercontent.com",
    "cdn.discordapp.com", "discord.com", "onedrive.live.com", "1drv.ms", "bitbucket.org", "gitlab.com",
    "mediafire.com", "www.mediafire.com", "t.me", "telegra.ph", "pastebin.com", "transfer.sh", "files.catbox.moe",
}


def read_hashes_bin(path):
    if not os.path.exists(path):
        return set()
    b = open(path, "rb").read()
    return {b[i:i + 32].hex() for i in range(0, len(b) - len(b) % 32, 32)}


def read_lines(path):
    if not os.path.exists(path):
        return set()
    return {l.strip().lower() for l in open(path) if l.strip() and not l.startswith("#")}


def write_bin(path, hashes):
    data = b"".join(bytes.fromhex(h) for h in sorted(hashes))
    open(path, "wb").write(data)
    return data


def sign(key_path, data):
    p = subprocess.run(["openssl", "dgst", "-sha256", "-sign", key_path], input=data, capture_output=True, check=True)
    return base64.b64encode(p.stdout)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--key", required=True, help="ECDSA P-256 private key (PEM)")
    ap.add_argument("--out", required=True)
    ap.add_argument("--previous", help="directory of the previously published bundle to merge")
    ap.add_argument("--offline", action="store_true", help="skip network sources")
    ap.add_argument("--host-ttl-days", type=int, default=90)
    a = ap.parse_args()

    os.makedirs(a.out, exist_ok=True)
    now = int(time.time())
    hashes, hosts_state = set(), {}
    if a.previous:
        hashes |= read_hashes_bin(os.path.join(a.previous, "threats.bin"))
        sp = os.path.join(a.previous, "hosts_state.json")
        if os.path.exists(sp):
            hosts_state = json.load(open(sp))
    hashes |= {h for h in read_lines(os.path.join(HERE, "extra_hashes.txt")) if SHA256.match(h)}

    if not a.offline:
        key = os.environ.get("ABUSECH_AUTH_KEY")
        if not key:
            sys.exit("ABUSECH_AUTH_KEY is not set (use --offline to sign local data only)")
        before = len(hashes)
        hashes |= mb_hashes(key)
        print(f"MalwareBazaar: +{len(hashes) - before} hashes")
        fresh = urlhaus_hosts(key)
        for h in fresh:
            hosts_state[h] = now
        print(f"URLhaus: {len(fresh)} active hosts")

    ttl = a.host_ttl_days * 86400
    hosts_state = {h: t for h, t in hosts_state.items() if now - t <= ttl and h not in SHARED_HOSTING}
    certs = {h for h in read_lines(os.path.join(HERE, "bad_certs.txt")) if SHA256.match(h)}

    files = []
    threats = write_bin(os.path.join(a.out, "threats.bin"), hashes)
    files.append({"name": "threats.bin", "sha256": hashlib.sha256(threats).hexdigest(), "count": len(hashes)})
    cert_bytes = write_bin(os.path.join(a.out, "certs.bin"), certs)
    files.append({"name": "certs.bin", "sha256": hashlib.sha256(cert_bytes).hexdigest(), "count": len(certs)})
    dom = ("\n".join(sorted(hosts_state)) + "\n").encode() if hosts_state else b""
    open(os.path.join(a.out, "domains.txt"), "wb").write(dom)
    files.append({"name": "domains.txt", "sha256": hashlib.sha256(dom).hexdigest(), "count": len(hosts_state)})
    json.dump(hosts_state, open(os.path.join(a.out, "hosts_state.json"), "w"), sort_keys=True)

    stamp = dt.datetime.now(dt.timezone.utc)
    manifest = {
        "format": 1,
        "version": int(stamp.strftime("%Y%m%d%H")),
        "generated": stamp.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "source": "MalwareBazaar, URLhaus (abuse.ch)",
        "files": files,
    }
    mbytes = json.dumps(manifest, indent=1).encode()
    open(os.path.join(a.out, "manifest.json"), "wb").write(mbytes)
    open(os.path.join(a.out, "manifest.sig"), "wb").write(sign(a.key, mbytes))
    print(f"bundle v{manifest['version']}: {len(hashes)} hashes, {len(certs)} certs, {len(hosts_state)} hosts -> {a.out}")


if __name__ == "__main__":
    main()
