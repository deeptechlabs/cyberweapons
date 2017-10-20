# Extract Service

This Assemblyline service extracts embedded files from file containers (like ZIP, RAR, 7z, ...)

**NOTE**: This service does not require you to buy any licence and is preinstalled and
working after a default installation

## Execution

The service mainly uses the 7zip library to extract files out of containers then resubmits them for
analysis. It will also use the python tnefparse lib to parse tnef files, the xxxswf library to extract 
compressed swf files, and unace to extract winace compressed files.

