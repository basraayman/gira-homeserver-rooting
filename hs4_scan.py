#!/usr/bin/env python3
"""Gira HomeServer 4 - multi-host vulnerability VERIFIER (read-only).

Owner-authorised / defensive use. Point this at one host, a list, or a CIDR
range and it reports which Gira HomeServers expose which findings, so a fleet
can be checked before and after a vendor fix.

Every probe is read-only or non-actuating, exactly as in hs4_poc_verify.py:
  - no KNX write/scene/timer opcodes
  - no project upload, no firmware, no shell, no persistence
It confirms the UNAUTHENTICATED findings (A pre-auth opcode dispatch, B user
oracle, C reflected XSS, D identity disclosure) and flags the firmware-write
path's precondition. It contains NO exploit for the code-execution findings.

Usage:
  hs4_scan.py <hs4-ip>
  hs4_scan.py <hs4-ip> <other-host> --user admin
  hs4_scan.py 192.168.1.0/24            # sweep a subnet for HomeServers, then verify
  hs4_scan.py --in hosts.txt --json results.json
"""
import argparse, ipaddress, json, os, sys, datetime

# reuse the audited, read-only probes from the single-host PoC
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from hs4_poc_verify import (Chan, http_get, http_body, quad_salt,
                            quad_preauth_ping, key_is_serial_derived)
import re, time


def is_homeserver(host, port):
    """Cheap, read-only fingerprint: the QUAD endpoint answers 100|| and /hs
    serves the German 'Anmeldung' form. Returns the serial if we can read it."""
    try:
        raw = http_body(http_get(host, port, "/HSADMIN?CMD=INIT&USER=admin", wait=4.0))
        m = re.search(rb"<SNO>(\w+)</SNO>", raw)
        if m:
            return True, m.group(1).decode()
    except Exception:
        pass
    try:
        c = Chan(host, port, timeout=4.0)
        c.send(b"GET /QUAD/LOGIN \r\n\r\n")
        if b"100|" in c.recv_until(2.0):
            c.close(); return True, None
        c.close()
    except Exception:
        pass
    return False, None


def verify_host(host, port, user, bad_user):
    res = {"host": host, "port": port, "is_homeserver": False, "serial": None,
           "findings": {}}
    hs, sno = is_homeserver(host, port)
    res["is_homeserver"] = hs
    res["serial"] = sno
    if not hs:
        return res

    # D - unauthenticated identity disclosure
    try:
        body = http_body(http_get(host, port, "/HSADMIN?CMD=INIT&USER=%s" % user)).decode("latin-1", "replace")
        key = (re.search(r"<KEY>([0-9a-fA-F]+)</KEY>", body) or [None, None])[1]
        serial = (re.search(r"<SNO>(\w+)</SNO>", body) or [None, None])[1]
        res["serial"] = res["serial"] or serial
        res["findings"]["D_identity_disclosure"] = bool(key and serial)
        res["findings"]["D_key_is_serial_derived"] = bool(key and serial and key_is_serial_derived(serial, key))
    except Exception as e:
        res["findings"]["D_identity_disclosure"] = "error: %r" % e

    # B - username oracle
    try:
        sg, sb = quad_salt(host, port, user), quad_salt(host, port, bad_user)
        res["findings"]["B_user_oracle"] = bool(sg) and not bool(sb)
    except Exception as e:
        res["findings"]["B_user_oracle"] = "error: %r" % e

    # A - application opcode dispatched pre-auth (benign ping; retried for QUAD starvation)
    try:
        time.sleep(1.5)
        ans = False
        for _ in range(4):
            ans, _log = quad_preauth_ping(host, port, user)
            if ans:
                break
            time.sleep(2.0)
        res["findings"]["A_preauth_opcode"] = bool(ans)
    except Exception as e:
        res["findings"]["A_preauth_opcode"] = "error: %r" % e

    # C - reflected XSS in /hshtm (benign marker)
    try:
        import urllib.parse
        q = "user=%s&pw=POCpw" % urllib.parse.quote('POCqq"><POCTAG>')
        body = http_body(http_get(host, port, "/hshtm?%s" % q)).decode("latin-1", "replace")
        res["findings"]["C_reflected_xss"] = '"><POCTAG>' in body
    except Exception as e:
        res["findings"]["C_reflected_xss"] = "error: %r" % e

    res["findings"]["E_firmware_write"] = "precondition-only: requires SATA (isSnowport); not probed remotely without auth"
    return res


def expand_targets(args):
    hosts = list(args.hosts)
    if args.infile:
        hosts += [l.strip() for l in open(args.infile) if l.strip() and not l.startswith("#")]
    out = []
    for h in hosts:
        if "/" in h:
            out += [str(ip) for ip in ipaddress.ip_network(h, strict=False).hosts()]
        else:
            out.append(h)
    return out


def main():
    ap = argparse.ArgumentParser(description="Gira HomeServer 4 multi-host verifier (read-only)")
    ap.add_argument("hosts", nargs="*", help="IPs, hostnames, or CIDR ranges")
    ap.add_argument("--in", dest="infile", help="file of hosts, one per line")
    ap.add_argument("--port", type=int, default=80)
    ap.add_argument("--user", default="admin")
    ap.add_argument("--bad-user", default="zzqqnope")
    ap.add_argument("--json", help="write full results as JSON")
    a = ap.parse_args()

    targets = expand_targets(a)
    if not targets:
        ap.error("give at least one host, CIDR, or --in file")

    when = datetime.datetime.now(datetime.timezone.utc).astimezone().isoformat()
    print("Gira HomeServer 4 verifier (read-only)  %s" % when)
    print("targets: %d\n" % len(targets))
    results = []
    FKEYS = [("A_preauth_opcode", "A"), ("B_user_oracle", "B"),
             ("C_reflected_xss", "C"), ("D_identity_disclosure", "D")]
    for host in targets:
        r = verify_host(host, a.port, a.user, a.bad_user)
        results.append(r)
        if not r["is_homeserver"]:
            if len(targets) <= 4:
                print("%-15s  not a HomeServer / unreachable" % host)
            continue
        flags = "".join(tag if r["findings"].get(key) is True else "." for key, tag in FKEYS)
        print("%-15s  HS4 serial=%-12s  findings[ABCD]=%s"
              % (host, r["serial"] or "?", flags))

    confirmed = [r for r in results if r["is_homeserver"]]
    print("\n%d HomeServer(s) found." % len(confirmed))
    if a.json:
        json.dump({"when": when, "results": results}, open(a.json, "w"), indent=2)
        print("wrote %s" % a.json)


if __name__ == "__main__":
    main()
