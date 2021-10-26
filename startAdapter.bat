powershell ./powerShell/killpy.ps1
echo "the adapter is going to start in the backend"
pythonw modbusTest.py daemon
echo "the adapter is started successfully"
pause