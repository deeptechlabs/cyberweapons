# SigCheck Service

This Assemblyline service uses the sigcheck application from sysinternals.

**NOTE**: This service does not require you to buy any licence and is preinstalled and working after a default installation

## Execution

Using the sigcheck tool, this service determines if a file is signed and if it was modified (post signature). 
It also looks for certificate authorities that are not typical.  This is a filtering service but it will 
also report if there is something suspicious related with the signature/certificate.

####Heuristics

**AL_SigCheck_001**: Invalid Signature

**AL_SigCheck_002**: Expired Signature

**AL_SigCheck_003**: Trusted Signers

**AL_SigCheck_004**: NonFiltered Signers

**AL_SigCheck_005**: Sigcheck Unexpected Behavior