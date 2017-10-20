# Oletools Service

This Assemblyline service extracts metadata and network information, and reports anomalies in Microsoft OLE and 
XML documents using the Python library py-oletools

**NOTE**: This service does not require you to buy a licence and is preinstalled and working after a default installation

## Execution

The Oletools service will report the following information for each file when present:

1. Macros (AL tag: TECHNIQUE_MACROS):
    * SHA256 (AL tag: OLE_MACRO_SHA256);
    * Suspicious strings (AL tak: OLE_MACRO_SUSPICIOUS_STRINGS);
    * Network indicators.

2. Embedded document streams
    * Name.

Extraction for both VBA scripts in macros and embedded streams is performed by the service.