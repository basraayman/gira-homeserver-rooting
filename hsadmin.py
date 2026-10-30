#!/usr/bin/env python3
"""Gira HomeServer /HSADMIN client (INIT + UPLOAD), reimplemented from the
decompiled hs_rpc.py / hs_load.py. Transport is /usr/bin/nc because macOS
local-network privacy only grants that binary on this host."""
import argparse, hashlib, io, re, selectors, struct, subprocess, sys, time, zipfile

NC = "/usr/bin/nc"


def nc_roundtrip(host, port, payload, wait, idle=1.5):
    p = subprocess.Popen([NC, host, str(port)], stdin=subprocess.PIPE,
                         stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
    sel = selectors.DefaultSelector(); sel.register(p.stdout, selectors.EVENT_READ)
    try:
        p.stdin.write(payload); p.stdin.flush()
    except BrokenPipeError:
        pass
    got = b""; deadline = time.time() + wait; last = time.time()
    while time.time() < deadline:
        if sel.select(timeout=0.3):
            d = p.stdout.read1(1 << 20)
            if not d:
                break
            got += d; last = time.time()
        elif got and time.time() - last > idle:
            break
    try: p.kill(); p.wait(timeout=2)
    except Exception: pass
    return got


def http_body(raw):
    i = raw.find(b"\r\n\r\n")
    return raw[i + 4:] if i >= 0 else raw


def keys(password):
    pw = (password.encode("latin-1") + b"\x00" * 64)[:64]
    k1 = bytes(b ^ 92 for b in pw)   # opad-ish
    k2 = bytes(b ^ 54 for b in pw)   # ipad-ish
    return k1, k2


def make_code(sdat, tan, password):
    """checkCodeInt(): md5(k1 + tan + upper(hex(md5(k2 + tan + sdat))))"""
    k1, k2 = keys(password)
    t = str(tan).encode()
    c1 = hashlib.md5(k2 + t + sdat.encode("latin-1")).hexdigest().upper().encode()
    return hashlib.md5(k1 + t + c1).hexdigest().upper()


def init(host, port, user):
    q = "CMD=INIT&USER=%s" % user
    raw = nc_roundtrip(host, port, ("GET /HSADMIN?%s HTTP/1.0\r\n\r\n" % q).encode(), 10)
    body = http_body(raw).decode("latin-1", "replace")
    m = {k: (re.search(p, body).group(1) if re.search(p, body) else None)
         for k, p in [("tan", r'tan="(\d+)"'), ("hnd", r"<HND>(\d+)</HND>"),
                      ("key", r"<KEY>([0-9a-f]+)</KEY>"), ("sno", r"<SNO>(\w+)</SNO>")]}
    return m, body


def upload(host, port, zbytes, tan, password, hnd):
    sdat = "CMD=UPLOAD&HND=%s" % hnd
    code = make_code(sdat, tan, password)
    query = "%s&CODE=%s" % (sdat, code)
    k1, k2 = keys(password)
    t = str(tan).encode()
    length = struct.pack("<I", 4 + len(zbytes) + 32)
    m = hashlib.md5(k2 + t); m.update(length); m.update(zbytes)
    trailer = hashlib.md5(k1 + t + m.hexdigest().upper().encode()).hexdigest().upper()
    req = ("GET /HSADMIN?%s HTTP/1.0\r\n\r\n" % query).encode()
    return nc_roundtrip(host, port, req + length + zbytes + trailer.encode(), 60, idle=4.0)


def mkzip(entries):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        for name, data in entries.items():
            z.writestr(name, data)
    return buf.getvalue()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", required=True)
    ap.add_argument("--port", type=int, default=80)
    ap.add_argument("--user", default="admin")
    ap.add_argument("--password", required=False)
    ap.add_argument("--version", default="000")
    ap.add_argument("--rollback", metavar="PRG.DAT",
                    help="upload this pristine prg.dat (+ version.dat) and reboot the HS")
    ap.add_argument("--probe", action="store_true",
                    help="upload a ZIP with a mismatched version.dat: pure no-op, reveals VERSION")
    a = ap.parse_args()

    meta, body = init(a.host, a.port, a.user)
    print("=== INIT (unauthenticated) ===")
    print("  " + body.strip().replace("\n", "\n  "))
    if not meta["tan"]:
        print("  !! no TAN - user unknown or IP blocked"); return 1
    print("  tan=%s hnd=%s sno=%s" % (meta["tan"], meta["hnd"], meta["sno"]))

    if a.rollback:
        if not a.password:
            print("--rollback needs --password"); return 2
        prg = open(a.rollback, "rb").read()
        z = mkzip({"version.dat": a.version + "\r\n", "prg.dat": prg})
        print("\n=== UPLOAD rollback: %d-byte prg.dat, then reboot ===" % len(prg))
        raw = upload(a.host, a.port, z, meta["tan"], a.password, meta["hnd"])
        hi = raw.find(b"HTTP/")
        if hi < 0:
            print("no HTTP response; head=%r" % raw[:120]); return 3
        resp = http_body(raw[hi:])
        zi = resp.find(b"PK\x03\x04")
        if zi < 0:
            print("no ZIP in response; head=%r" % resp[:200]); return 4
        zf = zipfile.ZipFile(io.BytesIO(resp[zi:]))
        print("uploaded, device rebooting. response entries: %s" % zf.namelist())
        return 0

    if a.probe:
        if not a.password:
            print("--probe needs --password"); return 2
        z = mkzip({"version.dat": a.version + "\r\n"})
        print("\n=== UPLOAD probe (version.dat=%r -> bok=0, no writes) ===" % a.version)
        raw = upload(a.host, a.port, z, meta["tan"], a.password, meta["hnd"])
        print("  %d bytes back" % len(raw))
        acks = raw.count(b"x") and len(re.findall(rb"x.{4}y", raw, re.S))
        print("  acks seen: %s" % acks)
        hi = raw.find(b"HTTP/")
        if hi < 0:
            print("  no HTTP response -> CODE rejected (block_ip, 5s) or framing off")
            print("  raw head: %r" % raw[:120]); return 3
        resp = http_body(raw[hi:])
        print("  response body %d bytes, head=%r" % (len(resp), resp[:40]))
        zi = resp.find(b"PK\x03\x04")
        if zi < 0:
            print("  no ZIP in response"); return 4
        try:
            zf = zipfile.ZipFile(io.BytesIO(resp[zi:-32] if len(resp) > zi + 32 else resp[zi:]))
            print("  >>> PASSWORD ACCEPTED - response ZIP entries: %s" % zf.namelist())
            for n in zf.namelist():
                d = zf.read(n)
                print("      %-14s %4d bytes  %r" % (n, len(d), d[:200]))
        except Exception as e:
            print("  ZIP parse issue: %r" % e)
            print("  raw: %r" % resp[zi:zi + 200])
    return 0


if __name__ == "__main__":
    sys.exit(main())
