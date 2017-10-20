# CaRT (Compressed and RC4 Transport)
The CaRT file format is used to store/transfer malware and it's asociated metadata. 
It neuters the malware so it cannot be executed and encrypt it so 
anti-virus softwares cannot flag the CaRT file as malware.

## Advantages

* FAST: CaRT is just as fast as zipping a file
* STREAMING: CaRT uses zlib and RC4 which allow it to encode files in streaming
* METADATA: CaRT can store the file metadata in the same file as the file itself, the metadata can be read without 
reading the full file
* HASH CALCULATION: CaRT calculates the hashes of the file while its encoding it and store that information in the 
footer
* SIZE: CaRT files are usually smaller then the original files because it uses compression. (Except in the case we you 
store huge amount of metadata in the CaRT)

## Using CaRT with stix v2
Now that stix v2 uses JSON as encoding, you can now bundle your stix report directly in the CaRT format. When CaRT encode files, it add metadata from *.cartmeta file with the same prefix of your file. Therefor if you save your stix report to a .cartmeta file, the resulting CaRT file will have the full stix report embedded with it.

Example:

    $ ls
      file.exe            - File I want to encode
      file.exe.cartmeta   - Stix report of file.exe

    $ cart file.exe
    $ ls
      file.exe            - File I want to encode
      file.exe.cartmeta   - Stix report of file.exe
      file.exe.cart       - CaRT file containig both the file.exe and it's stix report

## Format Overview

### Mandatory Header (38 bytes)

CaRT has a mandatory header that looks like this

     4s     h         Q        16s         Q
    CART<VERSION><RESERVED><ARC4KEY><OPT_HEADER_LEN>
    
Where VERSION is 1 and RESERVED is 0. It most of cases RC4 key used to decrypt the file is stored in the mandatory 
header and is always the same thing (first 8 digit of pi twice). Although, CaRT provides an option to override the key 
which then stores null bytes in the mandatory header. You'll then need to know the key to unCaRT the file...

### Optional Header (OPT_HEADER_LEN bytes)

CaRT's optional header is a OPT_HEADER_LEN bytes RC4 blob of a json serialized header

    RC4(<JSON_SERIALIZED_OPTIONAL_HEADER>)

### Data block (N Bytes)

CaRT's data block is a zlib then RC4 block 

    RC4(ZLIB(block encoded stream ))

### Optional Footer (OPTIONAL_FOOTER_LEN bytes)

Like the optional header, CaRT's optional footer is a OPT_FOOTER_LEN bytes RC4 blob of a json serialized footer

    RC4(<JSON_SERIALIZED_OPTIONAL_FOOTER>)

###  Mandatory Footer (32 Bytes)

CaRT ends its file with a mandatory footer which allow the format to read the footer and return the hashes without reading the whole file

     4s      QQ           Q
    TRAC<RESERVED><OPT_FOOTER_LEN>

## Command line interface 

By installing the pip package, you get access to the CaRT library and also access to the CaRT CLI. 

The CaRT CLI has the following priority for its options:

* There are defaults values for all the options inside the CLI
* Default values are overridden by options in ~/.cart/cart.cfg 
* Values in the configuration file are overridden by CLI options

These are the options available in the CaRT CLI:

    Usage: cart [options] file1 file2 ... fileN
    
    Options:
      --version             show program's version number and exit
      -h, --help            show this help message and exit
      -f, --force           Replace output file if it already exists
      -i, --ignore          Ignore RC4 key from conf file
      -j JSONMETA, --jsonmeta=JSONMETA
                            Provide header metadata as json blob
      -k KEY, --key=KEY     Use private RC4 key (base64 encoded). Same key must be
                            provided to unCaRT.
      -m, --meta            Keep metadata around when extracting CaRTs
      -n FILENAME, --name=FILENAME
                            Use this value as metadata filename
      -o OUTFILE, --outfile=OUTFILE
                            Set output file
      -s, --showmeta        Only show the file metadata

The CaRT configuration file look like this:

    [global]
    # rc4_key is a base64 representation of your key
    rc4_key: AvUzYXNkZg==
    # keep_meta is an equivalent to -m in the CLI
    keep_meta: True
    # force is an equivalent to -f in the CLI
    force: True
    
    # default_header is a key/value pair of data to be added to the CaRT in the optional header
    [default_header]
    poc: Your Name
    poc_email: your.name@your.org

------------------------------------------------------------------------------------------------------------------

# CaRT (Compressed and RC4 Transport)
Le format de fichier CaRT permet de stocker et de transférer les maliciels et les métadonnées connexes.
Il neutralise les maliciels de manière à ce qu’ils puissent être exécutés et chiffrés pour que le logiciel antivirus ne signale pas le fichier CaRT comme étant un maliciel.

## Avantages

* RAPIDE : Il est aussi rapide d’utiliser CaRT que de compresser un fichier.
* DIFFUSION EN CONTINU : CaRT utilise zlib et RC4, ce qui permet de coder les fichiers en cours de diffusion.
* MÉTADONNÉES : CaRT peut stocker les métadonnées d’un fichier dans le même fichier que le fichier lui-même; les métadonnées peuvent être lues sans qu'il soit nécessaire de lire le fichier en entier.
* CALCULS DE HACHAGE : CaRT calcule les condensés numériques du fichier parallèlement au codage du fichier, puis stocke l’information dans le pied de page.
* TAILLE : La taille des fichiers CaRT est généralement inférieure à celle des fichiers d’origine, puisqu’ils sont compressés (à moins qu’une grande quantité de métadonnées aient été stockées dans le CaRT).

## Utilisation de CaRT avec STIX v2
Maintenant que la version 2 de STIX utilise JSON aux fins de codage, vous pouvez grouper vos rapports STIX directement dans le format CaRT. Lorsque CaRT code les fichiers, il ajoute les métadonnées depuis le fichier *.cartmeta avec le même préfixe que celui utilisé par votre fichier. Par conséquent, si vous enregistrez votre rapport STIX dans un fichier .cartmeta, le rapport complet sera intégré dans le fichier CaRT résultant.

Par exemple :

    $ ls
      file.exe            - Fichier à coder
      file.exe.cartmeta   - Rapport STIX du fichier file.exe

    $ cart file.exe
    $ ls
      file.exe            - Fichier à coder
      file.exe.cartmeta   - Rapport STIX du fichier file.exe
      file.exe.cart       - Fichier CaRT contenant à la fois le fichier file.exe et son rapport STIX

## Aperçu du format

### En-tête obligatoire (38 octets)

CaRT comporte un en-tête obligatoire qui ressemble à ce qui suit :

     4s     h         Q        16s         Q
    CART<VERSION><RESERVED><ARC4KEY><OPT_HEADER_LEN>

Dans cet en-tête, la valeur de VERSION est 1 et celle de RESERVED est 0. Dans la plupart des cas, la clé RC3 utilisée pour déchiffrer le fichier y est stockée et elle est toujours la même (deux fois les 8 premiers chiffres de la valeur pi). CaRT propose toutefois une façon de remplacer la clé, laquelle consiste à stocker des octets nuls dans l’en-tête obligatoire. Vous devrez alors connaître la clé pour décoder le fichier CaRT.

### En-tête facultatif (OPT_HEADER_LEN octets)

L’en-tête facultatif de CaRT est un objet blob RC4 de OPT_HEADER_LEN octets tiré de l’en-tête sérialisé json

    RC4(<JSON_SERIALIZED_OPTIONAL_HEADER>)

### Bloc de données (N octets)

Le bloc de données de CaRT est d’abord une bibliothèque logicielle de compression de données (zlib), puis un bloc RC4

    RC4(ZLIB(block encoded stream))

### Pied de page facultatif (OPTIONAL_FOOTER_LEN octets)

Comme c’est le cas dans l’en-tête facultatif, le pied de page facultatif de CaRT est un objet blob RC4 de OPT_FOOTER_LEN octets tiré de l’en-tête sérialisé json

    RC4(<JSON_SERIALIZED_OPTIONAL_FOOTER>)

###  Pied de page obligatoire (32 octets)

Le ficher CaRT se termine par un pied de page obligatoire qui permet au format de lire le pied de page et de renvoyer les condensés numériques sans avoir à lire le fichier en entier :

     4s      QQ           Q
    TRAC<RESERVED><OPT_FOOTER_LEN>

## Interface de ligne de commande

En installant le gestionnaire de paquets pip, vous pouvez accéder à la bibliothèque de CaRT et au CLI de CaRT.

Le CLI de CaRT accorde les priorités suivantes à ses options :

* Des valeurs par défaut sont définies pour toutes les options à partir du CLI
* Les valeurs par défaut sont remplacées par des options dans ~/.cart/cart.cfg
* Les valeurs dans le fichier de configuration sont remplacées par les options du CLI

Des options sont disponibles dans le CLI de CaRT :

    Usage : cart [options] fichier1 fichier2 ... fichierN

    Options :
      --version             afficher le numéro de version du programme et quitter
      -h, --help            afficher ce message d’aide et quitter
      -f, --force           remplacer le fichier de sortie s’il existe déjà
      -i, --ignore          Ignorer la clé RC4 dans le fichier conf
      -j JSONMETA, --jsonmeta=JSONMETA
                            Fournir les métadonnées de l’en-tête sous forme d’objet blob json
      -k KEY, --key=KEY     Utiliser la clé RC4 privée (codé en Base64). La même clé doit être saisie pour décompresser le fichier CaRT.
      -m, --meta            Conserver les métadonnées lors de l’extraction des fichiers CaRT
      -n FILENAME, --name=FILENAME
                            Utiliser cette valeur comme nom de fichier des métadonnées
      -o OUTFILE, --outfile=OUTFILE
                            Définir le fichier de sortie
      -s, --showmeta        Afficher uniquement les métadonnées du fichier

Le fichier de configuration du CaRT ressemble à ce qui suit :

    [global]
    # rc4_key est une représentation en Base64 de votre clé
    rc4_key: AvUzYXNkZg==
    # keep_meta est un équivalent de -m dans le CLI
    keep_meta: True
    # force est un équivalent de -f dans le CLI
    force: True

    # default_header est une paire de données clé/valeur à ajouter à l’en-tête facultatif du fichier CaRT
    [default_header]
    poc: Votre nom
    poc_email: votre.nom@votre.org
