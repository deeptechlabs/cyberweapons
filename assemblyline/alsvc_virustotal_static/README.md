# VirusTotal Static Service

This Assemblyline service performs a hash check against the VirusTotal API and returns the results.

**NOTE**: This service **requires** you to have your own API key (Paid or Free). It is **not** preinstalled during a default installation.

## Execution

This service calls the [VirusTotal file report API](https://www.virustotal.com/vtapi/v2/file/report) with the hash of your file and returns the results (if any).

Because this service queries an external API, if selected by the user, it will prompt the user and notify them that their file or metadata related to their file will leave our system.

