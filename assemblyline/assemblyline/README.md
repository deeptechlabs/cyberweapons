# Assemblyline

Assemblyline is a scalable *__distributed file analysis framework__*. It is designed to process millions of files per day but can also be installed on a single box.

An Assemblyline cluster consists of 3 types of boxes: Core, Datastore and Worker.

## Components

### Assemblyline Core

The Assemblyline Core server runs all the required components to receive/dispatch tasks to the different workers. It hosts the following processes:

* Redis (Queue/Messaging)
* FTP (proftpd: File transfer)
* Dispatcher (Worker tasking and job completion)
* Ingester (High volume task ingestion)
* Expiry (Data deletion)
* Alerter (Creates alerts when score threshold is met)
* UI/API (NGINX, UWSGI, Flask, AngularJS)
* Websocket (NGINX, Gunicorn, GEvent)

### Assemblyline Datastore

Assemblyline uses Riak as its persistent data storage. Riak is a Key/Value pair datastore with SOLR integration for search. It is fully distributed and horizontally scalable.

### Assemblyline Workers

Workers are responsible for processing the given files.
Each worker has a hostagent process that starts the different services to be run on the current worker and makes sure that those service behave.
The hostagent is also responsible for downloading and running virtual machines for services that are required to run inside of a virtual machine or that only run on Windows.

### Assemblyline reference manual

If you want to know more about Assemblyline, you can get a copy of the full [reference manual](https://bitbucket.org/cse-assemblyline/assemblyline/src/master/manuals/). It can also be found in the `assemblyline/manuals` directory of your installation.

## Getting started

### Use as an appliance

An appliance is a full deployment that's self contained on one box/vm. You can easily deploy an Assemblyline appliance by following the appliance creation documentation.

[Install Appliance Documentation](docs/install_appliance.md)

### Deploy a production cluster

If you want to scan a massive amount of files then you can deploy Assemblyline as a production cluster. Follow the cluster deployment documentation to do so.

[Install Cluster Documentation](docs/install_cluster.md)

### Development

You can help us out by creating new services, adding functionality to the infrastructure or fixing bugs that we currently have in the system.

You can follow this documentation to get started with development.

#### Setup your development desktop

Setting up your development desktop can be done in two easy steps:

* Clone the Assemblyline repo
* run the setup script

##### Clone repo

First, create your Assemblyline working directory:

    export ASSEMBLYLINE_DIR=~/git/al
    mkdir -p ${ASSEMBLYLINE_DIR}

Then clone the main Assemblyline repo:

    cd $ASSEMBLYLINE_DIR
    git clone https://bitbucket.org/cse-assemblyline/assemblyline.git -b prod_3.2
    
##### Clone other repos

    ${ASSEMBLYLINE_DIR}/assemblyline/al/run/setup_dev_environment.py

**NOTE**: The setup script will use the same git remote that you've used to clone the Assemblyline repo

#### Setup your development VM

After you're done setting up your Desktop, you can setup the VM from which you're going to run your personal Assemblyline instance.

##### Local VM

If you want to use a local VM make sure your desktop is powerful enough to run a VM with 2 cores and 8 GB of memory.

You can install the OS by following this doc: [Install Ubuntu Server](docs/install_ubuntu_server.md)

##### (Alternative) Amazon AWS or other cloud providers

Alternatively you can use a cloud provider like Amazon AWS. We recommend 2 cores and 8 GB of ram for you Dev VM. In the case of AWS this is the equivalent to an m4.large EC2 node.

Whatever provider and VM size you use, make sure you have a VM with Ubuntu 14.04.3 installed.

##### Installing the assemblyline code on the dev VM

When you're done installing the OS on your VM, you need to install all Assemblyline components on that VM.

To do so, follow the documentation: [Install a Development VM](docs/install_development_vm.md)

#### Finishing setup

Now that the code is synced on your desktop and your Dev VM is installed, you should setup your development UI. Make sure to run the tweaks on your Dev VM to remove the id_rsa keys in order to have your desktop drive the code in your VM instead of the git repos.

If you have a copy of PyCharm Pro, you can use the remote python interpreter and remote deployment features to automatically sync code to your Dev VM. Alternatively, you can just manually rsync your code to your Dev VM every time you want to test your changes.

##### Setting up pycharm

Open PyCharm and open your project: ~/git/al (or ASSEMBLYLINE_DIR if you change the directory)

Pycharm will tell you there are unregistered git repos, click the 'add roots' button and add the unregistered repos.

###### Remote interpreter (pro only)

If you have the PyCharm Pro version you can set up the remote interpreter:

    file -> settings
    Project: al -> Project Interpreter

    Cog -> Add Remote

    SSH Credentials
    host: ip/domain of your VM
    user: al
    authtype: pass or keypair if AWS
    password: whatever password you picked in the create_deployment script

    click ok

**NOTE**: Leave the settings page opened for remote deployments. At this point you should be done with your remote interpreter. Whenever you click the play or debug button it should run the code on the remote Dev VM.

###### Remote Deployment (PyCharm Pro only)

Still in the settings page:

    Build, Execution, Deployment - > Deployment

    Plus button
    Name: assemblyline dev_vm
    Type: SFTP

    click OK

    # In the connection tab
    SFTP host: ip/domain of your VM
    User name: al
    authtype: pass or keypair if AWS
    password: whatever password you picked in the create_deployment script

    Click autodetect button

    Switch to Mappings page
    click "..." near Deployment path on server
    choose pkg
    click ok

**NOTE**: At this point you should be done with your remote deployment. When you make changes to your code, you can sync it to the remote Dev VM by opening the 'Version Control' tab at the bottom of the interface, selecting 'Local changes', right clicking on Default and selecting upload to 'assemblyline dev_vm'
#### Create a new service

To create a new service, follow the create service tutorial.

[Create service tutorial](docs/create_new_service.md)

-------------------------------------------------------------------------------------------

# Assemblyline

Assemblyline est un *__cadre d’analyse de fichiers distribué__*. Bien qu’il soit conçu pour traiter des millions de fichiers par jour, il est également possible de l’installer sur une seule machine.

Une grappe Assemblyline se compose de trois modules : Core, Datastore et Worker.

## Composantes

### Assemblyline Core

Le serveur Assemblyline Core exécute toutes les composantes requises pour recevoir et assigner les tâches aux différents workers. Il héberge les processus suivants :

* Redis (file d’attente/messagerie)
* FTP (proftpd: transfert de fichiers)
* Dispatcher (attribution et exécution des tâches)
* Ingester (ingestion d’un grand volume de tâches)
* Expiry (suppression de données)
* Alerter (création d’alertes lorsqu’un seuil donné est atteint)
* UI/API (NGINX, UWSGI, Flask, AngularJS)
* Websocket (NGINX, Gunicorn, GEvent)

### Assemblyline Datastore

Assemblyline utilise Riak pour le stockage permanent des données. Riak est une banque de données de paires clé-valeur permettant l’intégration SOLR aux fins de recherche. Elle est entièrement distribuée et offre une évolutivité horizontale.

### Assemblyline Workers

Les workers sont responsables du traitement des fichiers.
Chaque worker comporte un processus d’agent hôte qui lance les différents services à exécuter sur le worker en cours et veille au bon fonctionnement de ces services.
L’agent hôte est également responsable du téléchargement et de l’exécution des machines virtuelles pour les services qu’il faut exécuter sur une machine virtuelle ou qui ne s’exécutent que sur Windows.

### Manuel de référence d’Assemblyline

Pour en savoir plus sur Assemblyline, vous pouvez consulter le manuel de référence dans son intégralité (en anglais)(https://bitbucket.org/cse-assemblyline/assemblyline/src/master/manuals/). Vous le trouverez également dans le répertoire `assemblyline/manuals` de votre installation.

## Mise en route

### Utilisation d’une appliance

Une appliance est un déploiement complet et autonome effectué sur une machine virtuelle. Vous pouvez facilement déployer une appliance Assemblyline en suivant les directives fournies dans la documentation sur la création d’appliances (en anglais).

[Install Appliance Documentation](docs/install_appliance.md)

### Déploiement d’une grappe de production

Pour analyser une quantité considérable de fichiers, vous pouvez déployer Assemblyline en tant que grappe de production. Pour ce faire, suivez les directives fournies dans la documentation sur le déploiement de grappes (en anglais) :

[Install Cluster Documentation](docs/install_cluster.md)

### Développement

Vous pouvez nous aider à créer de nouveaux services, à ajouter des fonctionnalités à l’infrastructure ou à corriger les bogues dans le système actuel.

Pour commencer le développement, vous pouvez suivre les directives fournies dans le présent document.

#### Configuration de votre poste de développement

Il est possible de configurer votre poste de développement en deux étapes faciles :

* Cloner le dépôt d’Assemblyline
* Exécuter le script de configuration

##### Clonage du dépôt

Créez d’abord votre répertoire de travail Assemblyline :

    export ASSEMBLYLINE_DIR=~/git/al
    mkdir -p ${ASSEMBLYLINE_DIR}

Clonez ensuite le dépôt d’Assemblyline:

    cd $ASSEMBLYLINE_DIR
    git clone https://bitbucket.org/cse-assemblyline/assemblyline.git -b prod_3.2

##### Clonage des autres dépôts

    ${ASSEMBLYLINE_DIR}/assemblyline/al/run/setup_dev_environment.py

**REMARQUE** : Le script de configuration utilisera la même commande git remote utilisée pour cloner le dépôt d’Assemblyline.

#### Configuration de votre VM

Après avoir configuré votre poste de travail, vous pouvez configurer la machine virtuelle sur laquelle s’exécutera votre instance d’Assemblyline.

##### VM locale

Pour utiliser une VM locale, vous devez vous assurer que votre poste de travail est suffisamment puissant pour exécuter une VM bicœur avec 8 Go de mémoire.

Vous pouvez installer le SE en consultant le document suivant (en anglais) : [Install Ubuntu Server](docs/install_ubuntu_server.md)

##### (Facultatif) Amazon AWS et autres fournisseurs de services d’infonuagique

Il est également possible d’utiliser un fournisseur de services d’infonuagique comme Amazon AWS. La configuration recommandée pour votre VM de développement est 2 cœurs et 8 Go de mémoire RAM. AWS, notamment, est l’équivalent d’un nœud EC2 m4.large.

Quels que soient votre fournisseur et la taille de votre VM, vous devez vous assurer qu’Ubuntu 14.04.3 est installé sur votre VM.

##### Installation du code d’Assemblyline sur la VM de développement

Une fois le SE installé sur votre VM, vous devez installer toutes les composantes d’Assemblyline sur cette VM.

Pour ce faire, consultez le document suivant (en anglais) : [Install a Development VM](docs/install_development_vm.md)

#### Finalisation de la configuration

Maintenant que le code est synchronisé sur votre poste de travail et que votre VM de développement est installée, vous devez configurer votre IU de développement. Assurez-vous d’apporter les modifications mineures sur votre VM de développement pour supprimer les clés id_rsa de manière à ce que votre poste de travail exécute le code sur votre VM plutôt que dans les dépôts Git.

Si vous disposez d’une copie de PyCharm Pro, vous pouvez utiliser l’interpréteur Python distant et les fonctionnalités de déploiement à distance pour synchroniser automatiquement le code sur votre VM de développement. Sinon, vous pouvez synchroniser manuellement votre code sur votre VM de développement chaque fois qu’il est nécessaire de tester les modifications que vous apportez.

##### Configuration de pycharm

Ouvrez PyCharm et votre projet : ~/git/al (ou ASSEMBLYLINE_DIR si vous changez le répertoire)

Pycharm signalera la présence de dépôts Git non enregistrés. Cliquez sur le bouton add roots, puis ajoutez les dépôts non enregistrés.

###### Interpréteur distant (version pro uniquement)

Si vous disposez de la version professionnelle de PyCharm, vous pouvez configurer l’interpréteur distant :

    file -> settings
    Project: al -> Project Interpreter

    Cog -> Add Remote

    Justificateurs d’identité SSH
    host: ip/domaine de votre VM
    user: al
    authtype: pass ou keypair (avec AWS)
    password: n’importe quel mot de passe sélectionné à l’exécution du script create_deployment

    Cliquez sur OK

**REMARQUE** : Laissez la page de configuration ouverte pour les déploiements à distance. À ce stade, vous devriez avoir terminé la configuration de votre interpréteur distant. Le code s’exécutera sur votre VM de développement distante au moment où vous cliquerez sur le bouton Play ou Debug.

###### Déploiement à distance (PyCharm Pro uniquement)

Dans la page des paramètres :

    Build, Execution, Deployment - > Deployment

    Bouton Plus
    Name: assemblyline dev_vm
    Type: SFTP

    Cliquez sur OK

    # Dans l’onglet Connection
    SFTP host: ip/domaine de votre VM
    User name: al
    authtype: pass ou keypair (avec AWS)
    password: n’importe quel mot de passe sélectionné à l’exécution du script create_deployment

    Cliquez sur le bouton Autodetect

    Passez à la page Mappings
    Cliquez sur « ... » près du chemin d’accès Deployment du serveur
    Sélectionnez pkg
    Cliquez sur OK

**REMARQUE** : À ce stade, vous devriez avoir terminé la configuration de votre déploiement à distance. Lorsque vous apportez des modifications à votre code, vous pouvez le synchroniser sur la VM de développement distante. Vous devez, pour ce faire, ouvrir l’onglet Version Control au bas de l’interface, effectuer un clic droit sur Default, puis téléverser dans assemblyline dev_vm.

#### Création d’un nouveau service

Pour créer un nouveau service, suivez les directives mentionnées dans le tutoriel de création de service (en anglais) :

[Create service tutorial](docs/create_new_service.md)
