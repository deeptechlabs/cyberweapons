# PEFile Service

This Assemblyline service runs the PEFile application against windows executables.

**NOTE**: This service does not require you to buy any licence and is preinstalled and working after a default installation

## Execution

This services attempts to extract PE headers and provides the following information in the result output (when available):

- Entry point address
- Linker Version
- OS Version
- Time Date Stamp (AL tag: PE_LINK_TIME_STAMP)
- Machine Type
- RICH HEADER Info
- DATA DIRECTORY Info
- SECTIONS Info, including:
    - hash (AL tag: PE_SECTION_HASH)
- DEBUG Info, including:
    - PDB Filename (AL tag: PE_PDB_FILENAME)
- IMPORTs Info, including:
    - Table Listing
    - Import Hashes (AL tags: PE_IMPORT_MD5, PE_IMPORT_SORTED_SHA1)
- EXPORTs Info, including:
    - Module Name (AL tag: PE_EXPORT_MODULE_NAME)
- RESOURCES Info, including:
    - Name (AL tag: PE_RESOURCE_NAME)
    - Language (AL tag: PE_RESOURCE_LANGUAGE)
    - VersionInfo:
        - LangID
        - Original Filename (AL tag: PE_VERSION_INFO_ORIGINAL_FILENAME)
        - File Description (AL tag: PE_VERSION_INFO_FILE_DESCRIPTION)


