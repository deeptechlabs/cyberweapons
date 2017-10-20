set shell = CreateObject("WScript.Shell")
shell.Run "waitfornetworking.py", 1, 1 
Do
shell.Run "git --work-tree=c:\opt\al\pkg\assemblyline --git-dir=c:\opt\al\pkg\assemblyline\.git fetch", 1, 1
shell.Run "git --work-tree=c:\opt\al\pkg\assemblyline --git-dir=c:\opt\al\pkg\assemblyline\.git reset --hard origin/master", 1, 1
shell.Run "c:\opt\al\pkg\assemblyline\al\run\hostagent.py --sysprep", 1, 1
shell.Run "c:\opt\al\pkg\assemblyline\al\run\hostagent.py", 1, 1
wscript.sleep 5000
Loop
