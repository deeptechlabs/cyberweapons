# Cleaver Service

This Assemblyline service extracts metadata from files, mostly OLE2 files, using python's hachoir library.

**NOTE**: This service does not require you to buy any licence and is preinstalled and working after a default installation

## Execution

This service runs a legacy version of the python `hachoir` library and extracts metadata about given files. It is especially geared towards parsing the OLE2 format where it will actually drill down to its components to find anomalies.