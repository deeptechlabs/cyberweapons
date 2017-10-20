# Crowbar Service

NOTE: This service does not require you to buy any licence and is preinstalled and working after a default installation.

Static script de-obfuscator. 
The purpose is not to get surgical de-obfuscation, but rather to extract useful indicators (uses FrankenStrings patterns.py). 

### Stage 1 Modules (in order of execution):
1. HTML javascript extraction
### Stage 2 Modules (in order of execution):
1. VBE Decode - will create extracted file(s)
2. MSWord macro vars
3. Fake array vars
4. Simple XOR function
5. B64 Decode
6. Charcode
7. Charcode hex
8. String replace
9. Array of strings
10. Powershell vars
11. Concat strings
12. Powershell carets

