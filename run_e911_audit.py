import sys
import os
import re

#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
e911_audit.py

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

# We're gonna do it dirty right now from the console, later, we'll connect to the DB, or AGI or AMI or something
# We need to support both SIP and PJSIP extension which use different commands.

# asterisk binary
asteriskBIN = '/usr/sbin/asterisk'

ipDict = {}

# Get SIP extensions only, this is a different command and a different parse than PJSIP.
def getSIPExtensions():
    # asterisk command to get external IPs of registered extensions
    cmd = asteriskBIN + ' -rx "sip show peers" '
    # output is like this:
    #122/122                   127.12.17.90                           D  Yes        Yes         A  11889    OK (34 ms)                                   
    #124/124                   219.33.50.50                             D  Yes        Yes         A  13479    OK (31 ms)                                   

    # get the output of the command
    output = os.popen(cmd).read()

    # loop through the output and get the IP and extension number
    for line in output.split('\n'):
        if len(line) > 0:
            # split the line by spaces
            parts = line.split()
            # get the extension number
            ext = parts[0].split('/')[0]
            # go to the next if the ext is not numberic
            if not ext.isnumeric():
                continue
            # get the IP address
            ip = parts[1]
            # go to the next if the IP is not an IP address
            if not ip.count('.') == 3:
                continue

            # add the IP and extension to a dictionary
            # if the IP is not in the dictionary, add the IP as the key and the extension as the value
            if ip in ipDict:
                ipDict[ip][ext] = None
            else:
                ipDict[ip] = {ext: None}

# Get PJSIP extensions now
def getPJSIPExtensions():
    cmd = asteriskBIN + ' -rx "PJSIP show contacts"'
    # output is like this:
    # Contact:  115/sip:115@127.153.63.153:5887;x-ast-orig-host= 47e23d99a7 Avail        62.119
    # Contact:  120/sip:120@234.151.131.15:5555;x-ast-orig-hos 000b045248 Avail       143.726

    # get the output of the command
    output = os.popen(cmd).read()

    # loop through the output and get the IP and extension number
    for line in output.split('\n'):
        if len(line) > 0:
            # use a regex to match the extension number and IP address
            match = re.search(r'Contact:\s+\d+/sip[s]?:(\d+)@(\d+\.\d+\.\d+\.\d+)', line)
            if not match:
                continue
            # get the extension number
            ext = match.group(1)
            # get the IP address
            ip = match.group(2)

            # go to the next if the IP is not an IP address
            if not ip.count('.') == 3:
                continue

            # add the IP and extension to a dictionary
            # if the IP is not in the dictionary, add the IP as the key and the extension as the value
            if ip in ipDict:
                ipDict[ip][ext] = None
            else:
                ipDict[ip] = {ext: None}

# Get Emergency CID from asterisk in memory database, no need to connect to the DB.
def getEmergencyCID():
    # Lets pull a dict of extensions and their emergency CID
    # Later we can merge it with ipDict
    edict = {}
    # get the emergency CID for the extension
    cmd = asteriskBIN + ' -rx "database show"'
    output = os.popen(cmd).read()
    # There's a lot of output here, we need to find lines like:
    # /DEVICE/814/emergency_cid                         : 713652565    
    # Then we need to map the extension to the emergency CID in the ipDict dict

    # Loop through the output and get the extension number and emergency CID
    for line in output.split('\n'):
        if len(line) > 0:
            # use a regex to match the extension number and IP address
            match = re.search(r'/DEVICE/(\d+)/emergency_cid\s+:\s+(\d+)', line)
            if not match:
                continue
            # get the extension number
            ext = match.group(1)
            # get the emergency CID
            cid = match.group(2)
            # add the emergency CID to the dictionary
            edict[ext] = cid

    return edict


# Run the functions to get the SIP and PJSIP extensions into the Dict
getSIPExtensions()
getPJSIPExtensions()
eDict = getEmergencyCID()

# Now we need to merge the two dicts so that the extension key is updated with the emergency CID value
for ip in ipDict:
    for ext in ipDict[ip]:
        if ext in eDict:
            ipDict[ip][ext] = eDict[ext]

# sort the IP addresses
sortedIP = sorted(ipDict.keys())

# print the report
for ip in sortedIP:
    print(ip)
    for ext in sorted(ipDict[ip].keys()):
        print(f'    {ext} - {ipDict[ip][ext]}')
    print()

