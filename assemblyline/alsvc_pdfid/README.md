# PDFId Service

This Assemblyline service extracts metadata from PDFs using Didier Stevens python library PDFId.

**NOTE**: This service does not require you to buy any licence and is preinstalled and working after a default installation

## Execution

The PDFId service will report the following information for each file when present:

####PDF File Information

- PDF Header String
- Number of:
    - objects
    - streams
    - endstreams
    - xref
    - trailer
    - startxref
    - '/Page'
    - '/Encrypt'
    - '/Objstm'
    - '/JS'
    - '/Javascript'
    - '/AA'
    - '/OpenAction'
    - '/AcroForm'
    - '/JBIG2Decode'
    - '/RichMedia'
    - '/Launch'
    - '/Colours'
    - '%%EOF'
    - Bytes after %%EOF
- Total entropy
- Entropy inside streams
- Entropy outside streams
- Mod Date (AL tag: PDF_DATE_MOD)
- Creation Date (AL tag: PDF_DATE_CREATION)
- Last Modification Date (AL tag: PDF_DATE_LASTMODIFIED)
- Source Modified Date (AL tag: PDF_DATE_SOURCEMODIFIED)
- Modification Date (AL tag: PDF_DATE_PDFX)

####Heuristics

**AL_PDFID_001**: Launch command used.

**AL_PDFID_002**: There are byte(s) following the end of the PDF.

**AL_PDFID_003**: Looks for /JBIG2Decode. Using the JBIG2 compression.

**AL_PDFID_004**: Looks for /AcroForm.  This is an action launched by Forms.                              

**AL_PDFID_005**: Looks for /RichMedia.  This can be use to embed Flash in a PDF.

**AL_PDFID_006**: Date tag is ModDate. Will output the date value.

**AL_PDFID_007**: Date tag is CreationDate. Will output the date value.
                      
**AL_PDFID_008**: Date tag is LastModified. Will output the date value.

**AL_PDFID_009**: Date tag is SourceModified. Will output the date value.
                                   
**AL_PDFID_010**: Date tag is pdfx. Will output the date value.
                               
**AL_PDFID_011**: Found the /Encrypt string in the file.
