echo "try to find out the pythonw pid"
Get-WmiObject Win32_Process -Filter "name = 'pythonw.exe'" | Where-Object {$_.CommandLine -Match 'modbusTest.py'} | Select -ExpandProperty ProcessId