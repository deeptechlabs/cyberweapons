Using InstDrv
-------------

InstDrv has an interactive mode and a command line mode. If you start InstDrv
without parameters, you will run interactive mode.

In the interactive mode, you can type the full path of the driver and then
install it, start it, stop it or remove it. When installing the driver in
interactive mode, the driver is installed as "start on demand", meaning that
after a reboot, you must restart the driver manually. This is convenient during
development of the driver.

In command line mode, you pass the name of the driver (preferably including
its full path) and one or more options on the command line. The options are:
        /i      install the driver
        /u      remove (uninstall) the driver
        /s      silent: no popup messages case of errors
        /?      shows a help screen and then exits; other command line
                parameters are ignored

Example:
        instdrv /i /s c:\graphapp\drivers\vretrace.sys

In command line mode with the "/i" option, InstDrv installs the driver in
"auto start" mode, so that the driver is automatically started after each
reboot.

If an error occurs in command line mode, it switches to interactive mode,
unless the option "/s" was set. If you do not give an "/i" or "/u" options,
the utility also switches to command line mode --again, unless you set the
"/s" options. The "/s" option is therefore useful for a silent installation
of the driver.


Acknowledgements
----------------
InstDrv is a minor adaption from the LoadDrv utility that Paula Tomlinson
published in the article "Dynamically Loading Drivers in Windows NT" in
Windows Developer's Journal, May 1995. Source code for the LoadDrv utility
is still available through www.wdj.com.


License
-------
You are granted the right to use and distribute the InstDrv program in every
way that you see fit, provided that you agree not to hold me responsible for
any malfunction or damage that its use could cause.

