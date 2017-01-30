<script>
tzutil.exe /g
tzutil.exe /s "Tokyo Standard Time"
tzutil.exe /g
</script>

<powershell>
# Parameter Settings
Set-Variable -Name BootstrapScriptURL -Value "https://raw.githubusercontent.com/usui-tk/AWS-CloudInit_BootstrapScript/master/VPC(IPv4)/2nd-Bootstrap_WindowsServer2012R2-Base-Japan-HVM.ps1"

# Bootstrap Script Executite
cd "C:\Windows\TEMP"
Invoke-WebRequest -Uri $BootstrapScriptURL -OutFile 2nd-Bootstrap_WindowsServer2012R2-Base-Japan-HVM.ps1

powershell.exe -ExecutionPolicy RemoteSigned .\2nd-Bootstrap_WindowsServer2012R2-Base-Japan-HVM.ps1 -SkipNetworkProfileCheck
</powershell>

