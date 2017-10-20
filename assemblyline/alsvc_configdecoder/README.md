# ConfigDecoder Service

This Assemblyline service runs implant configuration extraction routines for implants identified by Yara rules.

**NOTE**: This service does not require you to buy any licence and is preinstalled and working after a default installation

## Execution

The service executes using these simple steps:

1. Runs a set of Yara rules against the file to try to identify it as part of an implant family
2. If an implant successfully identified, the service:

    2.1 Routes the file to an internal configuration block decoder
    
    2.2 Runs the decoder and extracts: Domains, IPs, Mutex names, Crypto keys and other configuration block information

## Rules

The Yara Rules for the different decoders are bundled with the service and are saved in the Riak signature bucket. They can be edited from there if they require tweaking. The service pulls the ruleset from Riak every time it restarts. It does not auto-update.