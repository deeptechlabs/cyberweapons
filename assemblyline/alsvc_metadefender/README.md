# MetaDefender Service

This Assemblyline service interfaces with the [Metadefender Core](https://www.opswat.com/metadefender-core) multi-scanning AV engine.

**NOTE**: This service **requires you to buy** a licence. It also **requires you to install** Metadefender Core on a seperate machine/VM. It is **not** preinstalled during a default installation

## Execution

The service uses the Metadefender Core API to send files to the server for analysis and report the results back to the user for all AV engines installed on the server.

## Installation of Metadefender Core

To install Metadefender Core you can follow our detailled documentation [here](mdcore_install/install_notes.md).

## Updates

This service supports auto-update in both online and offline environments. This is configurable in the service config.

## Licensing

The service was developed with Metadefender Core 4.x.

Contact your Metadefender Core reseller to get access to the licence you need for your deployment: [https://www.opswat.com/partners/channel-partners#find-a-partner](https://www.opswat.com/partners/channel-partners#find-a-partner)