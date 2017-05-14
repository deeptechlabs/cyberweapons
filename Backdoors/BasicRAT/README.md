# basicRAT

This is a cross-platform Python 2.x Remote Access Trojan (RAT), basicRAT was created to maintain a clean design full-featured Python RAT. Currently a work in progress and still being actively hacked on.

**Disclaimer: This RAT is for research purposes only, and should only be used on authorized systems. Accessing a computer system or network without authorization or explicit permission is illegal.**

## Features
* Cross-platform (Windows, Linux, and macOS)
* AES GCM encrypted C2 with D-H exchange
* Accepts connection from multiple clients
* Command execution
* File upload/download (a bit buggy since crypto change)
* Standard utilities (wget, unzip)
* System survey

## Usage
```
$ python basicRAT_server.py --port 1337

 ____    ____  _____ ____   __  ____    ____  ______      .  ,
|    \  /    |/ ___/|    | /  ]|    \  /    ||      |    (\;/)
|  o  )|  o  (   \_  |  | /  / |  D  )|  o  ||      |   oo   \//,        _
|     ||     |\__  | |  |/  /  |    / |     ||_|  |_| ,/_;~      \,     / '
|  O  ||  _  |/  \ | |  /   \_ |    \ |  _  |  |  |   "'    (  (   \    !
|     ||  |  |\    | |  \     ||  .  \|  |  |  |  |         //  \   |__.'
|_____||__|__| \___||____\____||__|\_||__|__|  |__|       '~  '~----''
         https://github.com/vesche/basicRAT

basicRAT server listening for connections on port 1337.

[?] basicRAT> help

client <id>         - Connect to a client.
clients             - List connected clients.
download <files>    - Download file(s).
execute <command>   - Execute a command on the target.
help                - Show this help menu.
kill                - Kill the client connection.
persistence         - Apply persistence mechanism.
quit                - Exit the server and end all client connections.
scan <ip>           - Scan top 25 TCP ports on a single host.
selfdestruct        - Remove all traces of the RAT from the target system.
survey              - Run a system survey.
unzip <file>        - Unzip a file.
upload <files>      - Upload files(s).
wget <url>          - Download a file from the web.

[?] basicRAT> clients
ID - Client Address
 1 - 127.0.0.1

[?] basicRAT> client 1

[1] basicRAT> execute uname -a
Linux sandbox3 4.8.13-1-ARCH #1 SMP PREEMPT Fri Dec 9 07:24:34 CET 2016 x86_64 GNU/Linux
```

## Build a stand-alone executable
Keep in mind that before building you will likely want to modify both the `HOST` and `PORT` variables located at the top of `basicRAT_client.py` to fit your needs.

On Linux you will need Python 2.x, [PyInstaller](http://www.pyinstaller.org/), and pycrypto. Then run something like `pyinstaller2 --onefile basicRAT_client.py` and it should generate a `dist/` folder that contains a stand-alone ELF executable.

On Windows you will need Python 2.x, PyInstaller, pycrypto, pywin32, and pefile. Then run something like `C:\path\to\PyInstaller-3.2\PyInstaller-3.2\pyinstaller.py --onefile basicRAT_client.py` and it should generate a `dist/` folder that contains a stand-alone PE (portable executable).

## Todo
* Interactive shell
* Client periodic connection attempt
* Client binary generation tool (cross-platform)
  * Pyinstaller
  * Switch options for remote IP, port, etc
* Persistence (cross-platform)
  * Windows: Registry keys, WMIC, Startup Dir
  * Linux: cron jobs, services, modprobe
  * macOS: LaunchAgent, LaunchDaemons
* Self-destruct (remove the RAT entirely)
* Privilege Escalation (getsystem-esque, dirty cow)
* Common C2 Protocols (HTTP, DNS)
* Clean log files
    * Linux: bash history, var logs, audit logs, etc
    * Windows: Event logs, prefetch, etc
* Screenshot
* Keylogger
* Expand toolkit (unrar, sysinfo)
* Scanning utilities (probe scan / ping sweep, scanning subnet)
* Password dumping (mimikatz / gsecdump)
* Tunneling / Pivoting (ssh)
* Anti-virus detection and evasion
* VM and Sandbox detection
* Exfil browser history
* Search file system for sensitive information using regex
    * addresses, credit cards numbers, socials, PII, etc
* Detect web cameras and take snapshots
* Steal wifi passwords

## Authors
* Austin Jackson [@vesche](https://github.com/vesche)
* Skyler Curtis [@deadPix3l](https://github.com/deadPix3l)

## Thanks
* [@bozhu](https://github.com/bozhu), AES-GCM Python implementation.
* [@reznok](https://github.com/reznok), multiple client connection prototype.

## Other open-source Python RATs for Reference
* [nathanlopez/Stitch](https://github.com/nathanlopez/Stitch)
* [n1nj4sec/pupy](https://github.com/n1nj4sec/pupy)
* [sweetsoftware/Ares](https://github.com/sweetsoftware/Ares)
* [ahhh/Reverse_DNS_Shell](https://github.com/ahhh/Reverse_DNS_Shell)
