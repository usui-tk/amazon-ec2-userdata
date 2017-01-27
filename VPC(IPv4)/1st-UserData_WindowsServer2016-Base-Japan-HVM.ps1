<script>
tzutil.exe /g
tzutil.exe /s "Tokyo Standard Time"
tzutil.exe /g
</script>

<powershell>
# Parameter Settings
Set-Variable -Name BootstrapScriptURL -Value "https://s3-ap-northeast-1.amazonaws.com/public-open-usui/2nd-Bootstrap_WindowsServer2016-Base-Japan-HVM.ps1"

# Bootstrap Script Executite
cd "C:\Windows\TEMP"
Invoke-WebRequest -Uri $BootstrapScriptURL -OutFile 2nd-Bootstrap_WindowsServer2016-Base-Japan-HVM.ps1

powershell.exe -ExecutionPolicy RemoteSigned .\2nd-Bootstrap_WindowsServer2016-Base-Japan-HVM.ps1 -SkipNetworkProfileCheck
</powershell>

