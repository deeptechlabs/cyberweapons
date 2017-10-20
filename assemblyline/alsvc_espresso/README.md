# Espresso Service

This Assemblyline service analyzes Java JAR files. All classes are extracted,
decompiled and analyzed for malicious behavior.

**NOTE**: This service does not require you to buy any licence and is preinstalled and
working after a default installation

## Execution

The service extracts all the files from inside the Jar then performs analysis of the different
files for malicious behavior. For all the `.java` files found inside the jar, the service will
run the `CFR Decompiler` tool on it to get back a human readable version of the code.

When a file inside the Jar is noted as potentially malicious, the file is added as a supplementary file
to the results so the analysts can see the content of that file.

