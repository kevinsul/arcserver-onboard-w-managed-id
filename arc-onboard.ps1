####  This script is used to connect to a Windows Server remotely using the PS Invoke-Command for the purposes of onboarding that server to Azure Arc.  ####

#we need to know which server to target, 
param (
    [string]$targetserver
)

############################The following is used to retrieve the Arc-enabled Server's access token and then used to retrieve admin username and password from key vault#######################
$apiVersion = "2020-06-01"
$resource = "https://vault.azure.net/"
$endpoint = "{0}?resource={1}&api-version={2}" -f $env:IDENTITY_ENDPOINT,$resource,$apiVersion
$secretFile = ""
try
{
    Invoke-WebRequest -Method GET -Uri $endpoint -Headers @{Metadata='True'} -UseBasicParsing
}
catch
{
    $wwwAuthHeader = $_.Exception.Response.Headers["WWW-Authenticate"]
    if ($wwwAuthHeader -match "Basic realm=.+")
    {
        $secretFile = ($wwwAuthHeader -split "Basic realm=")[1]
    }
}
Write-Host "Secret file path: " $secretFile`n
$secret = cat -Raw $secretFile
$response = Invoke-WebRequest -Method GET -Uri $endpoint -Headers @{Metadata='True'; Authorization="Basic $secret"} -UseBasicParsing
if ($response)
{
    $token = (ConvertFrom-Json -InputObject $response.Content).access_token
    Write-Host "Access token: " $token
}

###Retrieve the admin username and admine password secrets###
#$adminusername = Invoke-RestMethod -Uri <INPUT URL TO KV SECRET HERE CONTAINING ADMIN USERNAME>?api-version=2016-10-01 -Method GET -Headers @{Authorization="Bearer $token"}
#$adminpass = Invoke-RestMethod -Uri <INPUT URL TO KV SECRET HERE CONTAINING ADMIN PASSWORD>?api-version=2016-10-01 -Method GET -Headers @{Authorization="Bearer $token"}

$adminusername = Invoke-RestMethod -Uri https://arconboard-kv1.vault.azure.net/secrets/adminname?api-version=2016-10-01 -Method GET -Headers @{Authorization="Bearer $token"}
$adminpass = Invoke-RestMethod -Uri https://arconboard-kv1.vault.azure.net/secrets/adminpass?api-version=2016-10-01 -Method GET -Headers @{Authorization="Bearer $token"}
##########################################################################################################################################################################################################


##################################################create the $Cred variable in order to remotely connect to the target server using the proper local admin user/password.#########################################
$password = ConvertTo-SecureString $adminpass.value -AsPlainText -Force
$Cred = New-Object System.Management.Automation.PSCredential ($adminusername.value, $password)
#####################################################################################################################################################################################################################


########################################Run the following script block to install the Arc Agent using system token and local admin user/password on the target server##################################################
Invoke-Command -ComputerName $targetserver -ScriptBlock {
    

$global:scriptPath = $myinvocation.mycommand.definition

function Restart-AsAdmin {
    $pwshCommand = "powershell"
    if ($PSVersionTable.PSVersion.Major -ge 6) {
        $pwshCommand = "pwsh"
    }

    try {
        Write-Host "This script requires administrator permissions to install the Azure Connected Machine Agent. Attempting to restart script with elevated permissions..."
        $arguments = "-NoExit -Command `"& '$scriptPath'`""
        Start-Process $pwshCommand -Verb runAs -ArgumentList $arguments
        exit 0
    } catch {
        throw "Failed to elevate permissions. Please run this script as Administrator."
    }
}

try {
    if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        if ([System.Environment]::UserInteractive) {
            Restart-AsAdmin
        } else {
            throw "This script requires administrator permissions to install the Azure Connected Machine Agent. Please run this script as Administrator."
        }
    }  

    ###INPUT YOUR OWN VALUES HERE###
    $env:SUBSCRIPTION_ID = "00a1ec3b-475a-4c51-b020-d74c012c9c0f";
    $env:RESOURCE_GROUP = "arc-rg1";
    $env:TENANT_ID = "7c812b8f-fb02-4c38-becc-969bbae8b37b";
    $env:LOCATION = "eastus";
    $env:AUTH_TYPE = "principal";
    $env:CORRELATION_ID = "708433cd-7d87-445f-b294-86383ba961f8";
    $env:CLOUD = "AzureCloud";
    
    [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor 3072;
    Invoke-WebRequest -UseBasicParsing -Uri "https://aka.ms/azcmagent-windows" -TimeoutSec 30 -OutFile "$env:TEMP\install_windows_azcmagent.ps1";
    & "$env:TEMP\install_windows_azcmagent.ps1";
    if ($LASTEXITCODE -ne 0) { exit 1; }
    & "$env:ProgramW6432\AzureConnectedMachineAgent\azcmagent.exe" connect --access-token $Using:token --resource-group "$env:RESOURCE_GROUP" --tenant-id "$env:TENANT_ID" --location "$env:LOCATION" --subscription-id "$env:SUBSCRIPTION_ID" --cloud "$env:CLOUD" --correlation-id "$env:CORRELATION_ID";
}

catch {
    $logBody = @{subscriptionId="$env:SUBSCRIPTION_ID";resourceGroup="$env:RESOURCE_GROUP";tenantId="$env:TENANT_ID";location="$env:LOCATION";correlationId="$env:CORRELATION_ID";authType="$env:AUTH_TYPE";operation="onboarding";messageType=$_.FullyQualifiedErrorId;message="$_";};
    Invoke-WebRequest -UseBasicParsing -Uri "https://gbl.his.arc.azure.com/log" -Method "PUT" -Body ($logBody | ConvertTo-Json) | out-null;
    Write-Host  -ForegroundColor red $_.Exception;
}

} -Credential $Cred
