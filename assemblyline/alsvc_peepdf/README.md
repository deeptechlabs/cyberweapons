# PeePDF Service

This Assemblyline service uses the Python PeePDF library against PDF files. 

**NOTE**: This service does not require you to buy any licence and is preinstalled and working after a default installation

## Execution

The PeePDF service will report the following information for each file when present:

####PDF File Information

- MD5
- SHA1
- SHA256
- Size
- Version
- Binary (T|F)
- Linearized  (T|F)
- Encryption Algorithms
- Updates 
- Objects 
- Streams 
- Versions Info:
    - Catalog
    - Info
    - Objects
    - Streams
    - Xref streams
    - Compressed Objects
    - Encoded
    - Objects with JS code

####Heuristics

**AL_PeePDF_001**: Embedded PDF in XDP.

**AL_PeePDF_002**: A buffer was found in the javascript code.

**AL_PeePDF_003**: The eval() function is found in the javascript block. 

**AL_PeePDF_004**: The unescape() function is found in the javascript block. 

**AL_PeePDF_005**: Possible Javascript Shellcode.

**AL_PeePDF_006**: Unescaped Javascript Buffer.

**AL_PeePDF_007**: Suspicious Javascript.

####Other Items of Interest

- CVE identifiers
- Embedded files (will attempt to extract)
- Javascript (will attempt to extract)
- URL detection