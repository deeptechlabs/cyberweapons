# Symantec Service

This Assemblyline service interfaces with [Symantec's Protection Engine for Cloud Services](https://www.symantec.com/products/threat-protection/data-center-security/protection-engine-cloud-services) icap proxy.

**NOTE**: This service **requires you to buy** a licence. It also **requires you to install** SymantecPE on a seperate machine/VM. It is **not** preinstalled during a default installation

## Execution

The service uses our generic icap interface to send files to the proxy server for analysis and report the results back to the user.

## Installation of Symantec PE

To install Symantec PE you can follow our detailed documentation [here](icap_installation/install_notes.md).

## Updates

This service supports auto-update in both online and offline environments. This is configurable in the service config.

## Licensing

The service was developed with Symantec PE for linux Version: 7.8.0.141

Contact your Symantec reseller to get access to the licence you need for your deployment: [http://partnerlocator.symantec.com/](http://partnerlocator.symantec.com/)