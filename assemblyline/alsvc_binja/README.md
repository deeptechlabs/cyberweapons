# BinaryNinja APISig Service

This AssemblyLine service analyses Windows executables for the usage of specified API's within bounded ranges.

### Requirements ###

- [BinaryNinja](https://binary.ninja/index.html)
    - Compute licenses (Contact Support)
    - Current Dev Branch

### Installation ###

- binja.tar.gz
    - Must have folder 'binaryninja' containing your current installation of BinaryNinja.
- license.dat
    - Add a 'license' key to the Binja config, with a value of your license file contents.

### Signatures ###

- API Signatures are dictionaries stored as an array in sigs.json.
- Signature required keys:
    - name: The signature name, to be displayed on match
    - score: Score for each match of siganture
    - init: List of API Calls to start processing the signature at
    - conditions: List of conditions. Required keys for each condition:
        - max: Maximum distance to search for matching calls
        - tgts: The calls to match for this condition
- Example Signature
```json
{
  "name": "Lookup API And Call",
  "score": 10,
  "init": ["KERNEL32!LOADLIBRARY", "KERNEL32!GETMODULEHANDLE"],
  "conditions": [{"max": 10, "tgts": ["KERNEL32!GETPROCADDRESS"]},
                 {"max": 30, "tgts": ["REG"]}
                 ]
}
```

### Output ###

- Score, signature name and location of matching signatures
- Supplemental Files
    - The bndb generated during analysis
    - The linear disassembly of matched functions