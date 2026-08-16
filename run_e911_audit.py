#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
run_e911_audit.py

Description: This script will connect to asterisk DB and pull all extensions connected IP address, and
its emergency CID. Generate a report of all extensions in each location, sorted by IP address. We want to
know if any IP addresses are grouped together, but have different emergency CIDs (they should be the same
since theyre in the same location.) This should tell us phones that are in the same location but have different
caller IDs, or phones that are in different locations but have the same caller ID. Also should show us what
extensions are missing caller IDs. We're only pulling online extensions, since its a hassle to tell where they
are at if they're offline.

Author: Michael Palmer
Date: 2024-10-06
"""

import ipaddress
import re
import subprocess
import sys

# We're gonna do it dirty right now from the console, later, we'll connect to the DB, or AGI or AMI or something
# We need to support both SIP and PJSIP extension which use different commands.

# asterisk binary
asteriskBIN = '/usr/sbin/asterisk'

# Strings asterisk prints on stdout with a zero exit status, which would
# otherwise look like "no extensions found" instead of "the command failed".
CLI_ERROR_MARKERS = (
    'Unable to connect to remote asterisk',
    'No such command',
    'Command not found',
)


def is_cli_failure(returncode, output):
    """True if an asterisk -rx invocation did not actually produce a result.

    asterisk exits 0 even when the command is unknown or the daemon is
    unreachable, so the output has to be sniffed as well. An empty result is
    also treated as failure: every command here should print at least a header.
    """
    if returncode != 0:
        return True
    if not output.strip():
        return True
    return any(marker in output for marker in CLI_ERROR_MARKERS)


def run_asterisk_cmd(command):
    """Run `asterisk -rx <command>`. Returns (ok, output)."""
    try:
        proc = subprocess.run(
            [asteriskBIN, '-rx', command],
            capture_output=True,
            text=True,
        )
    except OSError as exc:
        return False, f'{asteriskBIN}: {exc}'

    output = proc.stdout + proc.stderr
    return not is_cli_failure(proc.returncode, output), output


def is_valid_ip(ip):
    """True for a real dotted-quad. Keeps junk out so the numeric sort is safe."""
    try:
        ipaddress.ip_address(ip)
    except ValueError:
        return False
    return True


def parse_sip_peers(output):
    """Parse `sip show peers` into a list of (ext, ip) for ONLINE peers only.

    Output is column-padded and looks like this:
    122/122         127.12.17.90    D  Yes  Yes  A  11889  OK (34 ms)
    130/130         10.0.0.55       D  Yes  Yes  A  5060   UNREACHABLE
    """
    peers = []
    for line in output.split('\n'):
        # Padding means "not empty" is not the same as "has content".
        if not line.strip():
            continue

        # Only peers asterisk can currently reach are in a known location.
        # UNREACHABLE/UNKNOWN/Unmonitored peers still print a last-known host,
        # which is exactly how a relocated phone gets filed under its old site.
        if 'OK (' not in line:
            continue

        parts = line.split()
        if len(parts) < 2:
            continue

        ext = parts[0].split('/')[0]
        if not ext.isnumeric():
            continue

        ip = parts[1]
        if not is_valid_ip(ip):
            continue

        peers.append((ext, ip))
    return peers


def parse_pjsip_contacts(output):
    """Parse `pjsip show contacts` into a list of (ext, ip) for Avail contacts.

    Output looks like this:
    Contact:  115/sip:115@127.153.63.153:5887;x-ast-orig-host= 47e23d99a7 Avail  62.119
    Contact:  120/sip:mac001565abcdef@234.151.131.15:5555;x-a 000b045248 Avail  143.726

    The extension is the AOR before the slash, NOT the user part of the
    contact URI -- Yealinks register using the device MAC.
    """
    contacts = []
    for line in output.split('\n'):
        if not line.strip():
            continue

        # Status is Avail / Unavail / Unknown / NonQual. \b keeps "Unavail"
        # from matching, since its 'a' is lowercase.
        if not re.search(r'\bAvail\b', line):
            continue

        match = re.search(
            r'Contact:\s+(\d+)/sips?:[^@]+@(\d+\.\d+\.\d+\.\d+)',
            line,
        )
        if not match:
            continue

        ext = match.group(1)
        ip = match.group(2)
        if not is_valid_ip(ip):
            continue

        contacts.append((ext, ip))
    return contacts


def normalize_cid(value):
    """Reduce a stored emergency_cid to one comparable form.

    The same emergency number gets stored several ways:
        7135551212   17135551212   <7135551212>   <17135551212>   +17135551212
    All of them are the same number, so all of them must reduce to the same
    string -- otherwise the report flags mismatches inside a location that
    are really just formatting differences.

    Punctuation is dropped and a NANP country code is stripped. Values that
    are not 11 digits starting with 1 are left alone, so anything that isn't
    a NANP number is not silently mangled.
    """
    digits = re.sub(r'\D', '', value)
    if len(digits) == 11 and digits.startswith('1'):
        digits = digits[1:]
    return digits


def parse_emergency_cids(output):
    """Parse `database show` into {ext: normalized cid}.

    Lines look like:
    /DEVICE/814/emergency_cid       : 713652565

    The value is taken whole and then normalized. Matching only bare digits
    would drop the <> and +1 forms entirely and report those extensions as
    having no emergency CID at all.
    """
    cids = {}
    for line in output.split('\n'):
        if not line.strip():
            continue

        match = re.search(r'/DEVICE/(\d+)/emergency_cid\s*:\s*(.*)$', line)
        if not match:
            continue

        ext = match.group(1)
        cid = normalize_cid(match.group(2))
        if not cid:
            continue

        cids[ext] = cid
    return cids


def sort_ips(ips):
    """Numeric sort, so hosts on a subnet stay adjacent in the report."""
    return sorted(ips, key=ipaddress.ip_address)


def sort_extensions(exts):
    return sorted(exts, key=int)


def main():
    ipDict = {}

    # chan_sip is gone on Asterisk 18+/FreePBX 16+, so a SIP failure alone is
    # not fatal -- but losing both collectors means there is no report to make.
    sipOK, sipOutput = run_asterisk_cmd('sip show peers')
    if not sipOK:
        print(f'WARNING: "sip show peers" failed, skipping SIP peers:\n{sipOutput.strip()}',
              file=sys.stderr)

    pjsipOK, pjsipOutput = run_asterisk_cmd('pjsip show contacts')
    if not pjsipOK:
        print(f'WARNING: "pjsip show contacts" failed, skipping PJSIP contacts:\n{pjsipOutput.strip()}',
              file=sys.stderr)

    if not sipOK and not pjsipOK:
        print('ERROR: could not collect extensions from either SIP or PJSIP. Aborting.',
              file=sys.stderr)
        return 1

    pairs = []
    if sipOK:
        pairs += parse_sip_peers(sipOutput)
    if pjsipOK:
        pairs += parse_pjsip_contacts(pjsipOutput)

    for ext, ip in pairs:
        ipDict.setdefault(ip, {})[ext] = None

    # A failed database show would render every extension as "missing CID",
    # which is the exact false alarm this audit exists to catch. Never guess.
    dbOK, dbOutput = run_asterisk_cmd('database show')
    if not dbOK:
        print(f'ERROR: "database show" failed, cannot read emergency CIDs. Aborting:\n{dbOutput.strip()}',
              file=sys.stderr)
        return 1
    eDict = parse_emergency_cids(dbOutput)

    # Now we need to merge the two dicts so that the extension key is updated with the emergency CID value
    for ip in ipDict:
        for ext in ipDict[ip]:
            if ext in eDict:
                ipDict[ip][ext] = eDict[ext]

    if not ipDict:
        print('No online extensions found.', file=sys.stderr)
        return 0

    # print the report
    for ip in sort_ips(ipDict.keys()):
        print(ip)
        for ext in sort_extensions(ipDict[ip].keys()):
            print(f'    {ext} - {ipDict[ip][ext]}')
        print()

    return 0


if __name__ == '__main__':
    sys.exit(main())
