# Sync Service

This Assemblyline service takes care of syncing the files across the different file transport layers in the system.

**NOTE**: This service does not require you to buy any licence and is preinstalled and working after a default installation

## Execution

This is a system service, it does not show up in the service selection list. It makes sure that for each file submitted to the system, it is copied to the different layers of file transport.

Assemblyline supports downloading files from multiple sources. The most common example is to have a near file transport layer on the same server as the web server so when a file is submitted to the web server it is directly dropped onto disk. These files would stay on disk for a short amount of time (5 to 10 minutes). Then you'd have a long term file storage of a central file server (NAS of some sort) and this would store the files until they expire inside the system. In this scenario, the sync service would ensure that for all submissions that are processing, the files would be accessible in both short term and long term file storage.