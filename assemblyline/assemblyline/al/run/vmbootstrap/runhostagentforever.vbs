set shell = CreateObject("WScript.Shell")
Do
wscript.sleep 5000
shell.Run "c:\opt\al\pkg\assemblyline\al\run\vmbootstrap\hostagent-bootstrap-stage-0.py", 1, 1
shell.Run "c:\opt\al\pkg\assemblyline\al\run\vmbootstrap\hostagent-bootstrap-stage-1.py", 1, 1
shell.Run "c:\opt\al\pkg\assemblyline\al\run\hostagent.py --sysprep", 1, 1
shell.Run "c:\opt\al\pkg\assemblyline\al\run\hostagent.py", 1, 1
Loop
