# Swiffer Service

This Assemblyline service extracts metadata and performs anomaly detection on 'audiovisual/flash' files.

**NOTE**: This service does not require you to buy any licence and is preinstalled and working after a default installation

## Execution

Swiffer will report the following information on each file when present:

####MetaData Extraction

SWF Header:
- Version
- FileLength
- FrameSize
- FrameRate
- FrameCount

Symbol Summary:
- Main Timeline
- TagIds
- Names

####Heuristics

**AL_Swiffer_001**: Checks for printable character buffers larger than 512 bytes (data also extracted from file when possible).

**AL_Swiffer_002**: Checks if the SWF was compiled within the last 24 hours.
                           
**AL_Swiffer_003**: Checks if the SWF contains embedded binary data (data will also be extracted from file when possible).

**AL_Swiffer_004**: Attempts disassembly and reports errors which may be indicative of intentional obfuscation.