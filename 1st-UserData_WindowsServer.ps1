<powershell>
# Parameter Settings(Script)
Set-Variable -Name DecisionScript -Option Constant -Scope Script -Value "https://raw.githubusercontent.com/usui-tk/AWS-CloudInit_BootstrapScript/master/2nd-Decision_WindowsServer-Version.ps1"

# Bootstrap Script Executite
cd "$Env:SystemRoot\Temp"
Invoke-WebRequest -Uri $DecisionScript -OutFile 2nd-Decision_WindowsServer-Version.ps1

powershell.exe -ExecutionPolicy Bypass .\2nd-Decision_WindowsServer-Version.ps1 -SkipNetworkProfileCheck
</powershell>
