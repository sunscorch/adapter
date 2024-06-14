echo "try to find pythonw pid"
$processid = Get-WmiObject Win32_Process -Filter "name = 'pythonw.exe'" | Where-Object {$_.CommandLine -Match 'modbusTest.py'} | Select -ExpandProperty ProcessId
echo $processid
If([String]::IsNullOrEmpty($processid))
{
 echo "there is no backend adapter running"
}
Else
{
echo "killing"
taskkill.exe /F /PID $(Get-WmiObject Win32_Process -Filter "name = 'pythonw.exe'" | Where-Object {$_.CommandLine -Match 'modbusTest.py'} | Select -ExpandProperty ProcessId)

}

echo "the adapter is going to start in the backend"
pythonw modbusTest.py daemon
echo "the adapter is started successfully"
