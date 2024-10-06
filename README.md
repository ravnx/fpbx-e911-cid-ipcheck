# fpbx-e911-cid-ipcheck
For FreePBX - Make a report of SIP and PJSIP extensions and their Emergency CID's - Helps us sort out who's moved phones

## Details
This script will connect to asterisk DB and pull all extensions connected IP address, and
its emergency CID. Generate a report of all extensions in each location, sorted by IP address. We want to 
know if any IP addresses are grouped together, but have different emergency CIDs (they should be the same 
since theyre in the same location.) This should tell us phones that are in the same location but have different
caller IDs, or phones that are in different locations but have the same caller ID. Also should show us what 
extensions are missing caller IDs. We're only pulling online extensions, since its a hassle to tell where they
are at if they're offline.

## Requirements
Python3

## Configure
You may need to change your asterisk location, or if you find a bug in the regex that i missed, you might have to fix it.
