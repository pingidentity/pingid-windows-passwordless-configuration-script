#Execution Order
#1. Run validations - admin rights and AD module
#2. Select PingOne Enviornemnt
#3. Create CA certificate, install to NTAuth store, install to Trusted Root store in GPO
#4. Set unique user attribute
#5. Create Windows Passwordless Flow
#6. Create SOP, use The created flow
#7. Create Application, use the created SOP and CA certificate
#8. Issue a KDC certificate and install it to the Personal store

$apiEnviornements="environments"
$apiKeys="keys"
$apiSchemas="schemas"
$apiFlowDefinitions="flowDefinitions"
$apiSignOnPolicies="signOnPolicies"
$apiApplications="applications"
$date=Get-Date -UFormat "%m-%d-%Y"

function RunValidations{
    $currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    if(!$currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)){
        Write-Error "Missing administrative rights, can not execute"
        Exit 1
    }

    if (!(Get-Module -ListAvailable -Name 'ActiveDirectory')){
        Write-Error "Missing module, this script must run on Active Directory server"
        Exit 1
    }
}
function Run{
    Write-Host "Welcome to PingID Windows Passwordless configuration wizard"

    RunValidations
    if (!$global:accessToken){
        $global:accessToken =  Read-Host  "Enter PingOne access token" | ConvertTo-SecureString -AsPlainText
    }else{
        $global:accessToken =  $global:accessToken | ConvertTo-SecureString -AsPlainText
    }
    $global:apiBase=getBasueUrlFromToken
    ############Read Env
    selectEnv
    Write-Host "Selected enviornment: " $global:envId " " $global:envName

    ############Create CA
    Write-Host "Creating an issuance (CA) certificate"
    createCACertificate

    ############Make External ID Unique
    Write-Host "Setting ExternalID Attribute as Unique"
    setExternalIDUnique

    ############Create Flow Definition 
    Write-Host "Creating Authentication Flow"
    createFlowDefinition

    ############Create SOP
    Write-Host "Creating Signon Policy"
    createSop

    ############Create Application
    Write-Host "Creating OIDC Application"
    #TODO: Fix App configation (redirect URL etc...)
    createApp

    ###########Create KDC Cert
    Write-Host "Creating KDC certificate"
    kdcCert

    Write-Host "To install PingID Windows Login Passwordless on the endpoint PC Run the following command:"
    Write-Host "  WinLogin_passwordless_1.0_installer.exe /EnvID=$global:EnvId /AppID=$global:AppId /AppSecret=$global:AppSecret"
    Write-Host "Done"
}
function selectEnv{
    $environments = Invoke-Api -Method 'GET' -QueryParams 'expand=billOfMaterials'
    $i=1;
    $validEnvs=@()
    $environments._embedded.environments | Foreach-Object -Process{
        $_envId=$_.id
        $_envName=$_.name
        $_._embedded.billOfMaterials.products | Foreach-Object -Process{
            if (($_.type -eq "PING_ID") -and ($_.deployment -ne $null)){
                Write-Host $i. $_envId $_envName $_.type
                $i++;
                $validEnvs=$validEnvs + @([pscustomobject]@{id=$_envId; name=$_envName})
            }
        }
    }
    $i--
    $envNo=Read-Host "Select an enviornment (1-$i)"
    $envNo=[int]$envNo
    $envNo--
    $global:envId=$validEnvs[$envNo].id
    $global:envName=$validEnvs[$envNo].name

    write-debug $envId
}

function createCACertificate{
    $defauktCaCertCN = "Windows Passwordless Login CA " + $date
    if (!($caCertCN = Read-Host "Common Name [$defauktCaCertCN]")) { $caCertCN = $defauktCaCertCN }
    $caCertO = Read-Host "Organization []"
    $caCertOU = Read-Host "Organizational Unit []"
    $caCertL = Read-Host "City []"
    $caCertST = Read-Host "State []"
    $caCertC = Read-Host "Country []"
    $caCertDn="cn=$caCertCn, O=$caCertO, OU=$caCertOU, L=$caCertL, ST=$caCertST, C=$caCertC"

    $request=@{
        "name"= "$caCertCN"
        "default"= $false
        "subjectDN"= "$caCertDn"
        "algorithm"= "RSA"
        "keyLength"= 2048
        "validityPeriod"= 365
        "signatureAlgorithm"= "SHA256withRSA"
        "usageType"= "ISSUANCE"
        "status"= "VALID"
    }  
    
    $cert = Invoke-Api -Method "POST" -Body $request -Endpoint $apiKeys
    
    $certLink = $cert._links.self.href
    $global:IssuanceCertId=$cert.id
    Write-Host "Downloading certificate: $certLink..."
    Invoke-Api -Method 'GET' -Endpoint $apiKeys -ResourceId $cert.id -AsPem $true -OutFile "$caCertCN.crt"
    $certFileName = "$(Get-Location)\$caCertCN.crt"
    Write-Host "Done $certFileName"

    Write-Host "Installing certificate to Enterprise NTAuth store..."
    if ((Read-Host "Do you whish to skip this step? (y/n)").ToLower() -ne "y") {Write-Host "Skiping..." return}
    Write-Host 'certutil -dspublish -f "'$caCertCN'.crt" NTAuthCA'
    $error.Clear()
    certutil -dspublish -f "$caCertCN.crt" NTAuthCA
    write-debug "ExitCode: $lastExitCode"
    if ($lastExitCode -ne 0) {
         Write-Error "Failed To Execute Command: "
         Exit $lastExitCode
    }

    installCACertGpo -CertFilePath $certFileName
}

function setExternalIDUnique{
    $defaultAttributeName="externalId"
    if (!($attributeName = Read-Host "Common Name [$defaultAttributeName]")) { $attributeName = $defaultAttributeName }

    $schemas=Invoke-API -Method 'GET' -Endpoint $apiSchemas
    $attributes=Invoke-API -Method 'GET' -Url $schemas._embedded.schemas._links.attributes.href
    $attributes._embedded.attributes  | Foreach-Object -Process{
        if ($_.name -eq "$attributeName"){
            $externalIdLink= $_._links.self.href
        }
    }
    $request=@{
        "type" = "STRING"
        "unique" = $true
        "enabled" = $true
    }
    Invoke-API -Method 'PATCH' -Url $externalIdLink -Body $request

}

function createFlowDefinition{
    $flowDef=ConvertFrom-Json -InputObject '{
        "name": "Windows Passwordless - auto-generatd ",
        "enabled": true,
        "trigger": {
            "type": "EXPERIENCE",
            "next": "lookup-user"
        },
        "stepDefinitions": {
            "lookup-user": {
            "configuration": {
                "matchAttributes": [
                "externalId"
                ],
                "matchPingOneUsersOnly": false
            },
            "input": {
                "identifier": "${flow.inputs.context.authorizationRequest.loginHint}"
            },
            "outlets": {
                "PING_ONE_USER_MATCHED": {
                "next": "machine-passwordless",
                "displayName": "PingOne User Matched"
                },
                "IDENTITY_PROVIDER_USER_MATCHED": {
                "next": "machine-passwordless",
                "displayName": "Identity Provider User Matched"
                }
            },
            "type": "USER_LOOKUP",
            "displayName": "Lookup User"
            },
            "machine-passwordless": {
            "configuration": {
                "offlineMode": false
            },
            "input": {
                "user": {
                "id": "${steps.lookup-user.outputs.user.id}",
                "username": "${steps.lookup-user.outputs.user.username}"
                },
                "application": {
                "id": "${flow.inputs.context.application.id}"
                }
            },
            "outlets": {
                "SUCCEEDED": {
                "next": "complete-flow",
                "displayName": "Succeeded"
                }
            },
            "type": "MACHINE_PASSWORDLESS",
            "displayName": "Machine Passwordless"
            },
            "complete-flow": {
            "configuration": {
                "result": "REDIRECT"
            },
            "input": {
                "parameters": {
                "flowExecutionId": "${flow.id}"
                },
                "context": {
                "amr": "${steps.machine-passwordless.outputs.amr}",
                "user": {
                    "id": "${steps.lookup-user.outputs.user.id}"
                }
                }
            },
            "type": "COMPLETE_FLOW",
            "displayName": "Complete Flow"
            }
        }
        }'
    
    $flowDef.name += $date
    $flow=Invoke-Api -Method 'POST' -Body $flowDef -endpoint $apiFlowDefinitions
    $global:flowId = $flow.id
    $flow
    Write-Host "Done"
}

function createSop{
    $sopReq = ConvertFrom-Json -InputObject '{"default":false,"name":"Windows_Passwordless_auto_generatd_","environmentId":null}'
    $actionsReq = ConvertFrom-Json -InputObject '{"priority":1,"type":"EXPERIENCE","flowDefinition":{"id":""}}'
    $sopReq.name += $date
    $actionsReq.flowDefinition.id=$global:flowId

    $sop=Invoke-Api -Method 'POST' -Body $sopReq -Endpoint $apiSignOnPolicies
    $sop
    $global:sopId=$sop.id
    $actions=Invoke-Api -Method 'POST' -Body $actionsReq -Url $sop._links.actions.href
    $actions
    Write-Host "Done"
}

function createApp{
    $appsReq= ConvertFrom-Json -InputObject '{
        "enabled": "true",
        "redirectUris": [
            "https://foo.com"
        ],
        "name": "Windows Passwordless - auto-generatd ",
        "kerberos": {
            "key": {
                "id": ""
            }
        },
        "tokenEndpointAuthMethod": "NONE",
        "rolesSelected": [],
        "responseTypes": [
            "CODE",
            "TOKEN",
            "ID_TOKEN"
        ],
        "protocol": "OPENID_CONNECT",
        "type": "NATIVE_APP",
        "grantTypes": [
            "AUTHORIZATION_CODE",
            "IMPLICIT"
        ]
    }'
    $appsReq.kerberos.key.id = $global:IssuanceCertId
    $appsReq.name += $date
    $sopAssginmentReq = ConvertFrom-Json -InputObject '{signOnPolicy: {id: ""}, priority: 1}'
    $sopAssginmentReq.signOnPolicy.id=$global:sopId    

    $app=Invoke-API -Method 'POST' -Body $appsReq -Endpoint $apiApplications
    $global:appLink = $app._links.self.href
    $global:appId = $app.id
    $global:appSecret = (Invoke-API -Method 'GET' -Url $app._links.secret.href).secret
    $app
    $sopAssignmentsEndpoint=$app._links.self.href+"/signOnPolicyAssignments"
    $appPolicy=Invoke-API -Method 'POST' -Body $sopAssginmentReq -Url $sopAssignmentsEndpoint
    $appPolicy
    Write-Host 'Done'
}

function kdcCert{

    if ((Read-Host "Do you whish to continue execution of this step? (y/n)").ToLower() -ne "y") {Write-Host "Skiping..." return}
    $dnsName=[System.Net.DNS]::GetHostByName($Null).hostname
    $config='
        [newrequest]
        subject = "CN='+$dnsName+'"
        KeyLength = 2048
        MachineKeySet = TRUE
        Exportable = FALSE
        RequestType = PKCS10
        SuppressDefaults = TRUE
        [Extensions]
        ;Note 2.5.29.17 is the OID for a SAN extension.
        2.5.29.17 = "{text}"
        _continue_ = "dns='+$dnsName+'&"'

    $config | Out-File -FilePath '.\confg.temp.inf'
    Write-Host 'Creating certificate request: kdc.req'
    certreq -new 'confg.temp.inf' 'kdc.req'
    if ($lastExitCode -ne 0) {
         Write-Error "Failed To Execute Command: "
         Exit $lastExitCode
    }

    Write-Host "Issuing certificate from the request, using issuace certificate ID: $global:IssuanceCertId"
    Invoke-MultipartFormDataUpload -Uri $global:appLink'/kdcCSR?validityDuration=31536000' -InFile 'kdc.req' -OutFile '.\kdc.cer'

    Write-Host 'Installing certificate to Local Macine, "Personal" key storage'
    certreq -accept -machine -f 'kdc.cer'
    if ($lastExitCode -ne 0) {
        Write-Error "Failed To Execute Command: "
        Exit $lastExitCode
    }
}

#Helper functions
function Api-Path-Builder{
    [CmdletBinding()]
	param(     
        [string][Parameter()]$Endpoint,  
        [string][Parameter()]$ResourceId,
        [string][Parameter()]$QueryParams
    )

    
    if ($Endpoint){
        if($ResourceId){
            $url = "$global:apiBase/$apiEnviornements/$global:envId/$Endpoint/$ResourceId"
        }else{
            $url = "$global:apiBase/$apiEnviornements/$global:envId/$Endpoint"
        }
    }else{
        $url = "$global:apiBase/$apiEnviornements"
    }
    if ($QueryParams){
        $url += "?$QueryParams"
    }
    return $url
}

function Invoke-API{
	[CmdletBinding()]
	param(
		[string][Parameter(Mandatory)][ValidateSet('GET','POST','UPDATE','DELETE', 'PATCH')]$Method,
        [Parameter()][PSCustomObject]$Body,
        [Parameter()][bool]$AsPem,
        [Parameter()][string]$Endpoint,
        [Parameter()][string]$ResourceId,
        [Parameter()][string]$QueryParams,
        [Parameter()][string]$OutFile,
        [Parameter()][bool]$Multipart,
        [Parameter()][string]$Url
	)

    try{
        if ($Url){
            $_url=$Url
        }else{
            $_url = Api-Path-Builder -Endpoint $Endpoint -ResourceId $ResourceId -QueryParams $QueryParams
        }
        if ($AsPem){
            $headers = @{
                'accept' = 'application/x-x509-ca-cert, application/x-pem-file'
            }
        }else{
            $headers = @{
                'accept' = 'application/json'
            }
        }
        

        Write-Debug "$Method $_url $OutFile"
        ($headers | Out-String -Stream) -ne '' | select -Skip 2  | Write-Debug
        if (($Method -eq 'POST') -or ($Method -eq 'UPDATE') -or ($Method -eq 'PATCH')){
            if ($Multipart){
                return Invoke-RestMethod -Method $Method -Uri $_url -Authentication 'OAuth' -Token $global:accessToken -Body $Body -Headers $headers -OutFile $OutFile
            }else{
                $bodyJson = $Body | ConvertTo-Json -Depth 10
                Write-Debug $bodyJson
                return Invoke-RestMethod -Method $Method -Uri $_url -Authentication 'OAuth' -Token $global:accessToken -Body $bodyJson -ContentType "application/json" -Headers $headers -OutFile $OutFile
            }
        }else{
            return Invoke-RestMethod -Method $Method -Uri $_url -Authentication 'OAuth' -Token $global:accessToken -ContentType "application/json" -Headers $headers  -OutFile $OutFile
        }
    }
    catch { 
        if ($_.Exception.Response){
            Write-Error $_.Exception.Response
        }else{
            
            Write-Error $_.Exception
        }
        Exit 1
    }
}

function Invoke-MultipartFormDataUpload{
    [CmdletBinding()]
    param
    (
        [string][parameter(Mandatory = $true)][ValidateNotNullOrEmpty()]$InFile,
        [string][parameter(Mandatory = $true)][ValidateNotNullOrEmpty()]$OutFile,
        [Uri][parameter(Mandatory = $true)][ValidateNotNullOrEmpty()]$Uri
    )
    try{
        $ContentType = "application/octet-stream"
        Add-Type -AssemblyName System.Net.Http

        $httpClientHandler = New-Object System.Net.Http.HttpClientHandler
        $httpClient = New-Object System.Net.Http.Httpclient $httpClientHandler
        $packageFileStream = New-Object System.IO.FileStream @("$pwd\$InFile", [System.IO.FileMode]::Open)
        
        $contentDispositionHeaderValue = New-Object System.Net.Http.Headers.ContentDispositionHeaderValue "form-data"
        $contentDispositionHeaderValue.Name = "file"
        $contentDispositionHeaderValue.FileName = (Split-Path $InFile -leaf)
        $httpClient.DefaultRequestHeaders.Authorization = New-Object System.Net.Http.Headers.AuthenticationHeaderValue('Bearer', (ConvertFrom-SecureString -AsPlainText -SecureString $global:accessToken))

        $streamContent = New-Object System.Net.Http.StreamContent $packageFileStream
        $streamContent.Headers.ContentDisposition = $contentDispositionHeaderValue
        $streamContent.Headers.ContentType = New-Object System.Net.Http.Headers.MediaTypeHeaderValue $ContentType
        $content = New-Object System.Net.Http.MultipartFormDataContent
        $content.Add($streamContent)
    
        $httpClient.DefaultRequestHeaders
        $response = $httpClient.PostAsync($Uri, $content).Result
        if (!$response.IsSuccessStatusCode){
            $responseBody = $response.Content.ReadAsStringAsync().Result
            $errorMessage = "Status code {0}. Reason {1}. Server reported the following message: {2}." -f $response.StatusCode, $response.ReasonPhrase, $responseBody
            throw [System.Net.Http.HttpRequestException] $errorMessage
        }
        $responseBody=$response.Content.ReadAsStringAsync().Result
        $responseBody | Out-File -FilePath $OutFile
        return $responseBody
    }
    catch{
        write-Error $_
        Exit 1
    }
    finally{
        if ($null -ne $httpClient){ $httpClient.Dispose() }
        if ($null -ne $response){ $response.Dispose() }
        if ($null -ne $streamContent) { $streamContent.Dispose() }
        if ($null -ne $packageFileStream) { 
            $packageFileStream.Close()
            $packageFileStream.Dispose()
        }
    }
}

function installCACertGpo{
    [CmdletBinding()]
    param
    (
        [string][parameter(Mandatory = $true)][ValidateNotNullOrEmpty()]$CertFilePath
    )

    Write-Host "Installing CA Certificate to Group Policy..."
    if ((Read-Host "Do you whish to continue execution this step? (y/n)").ToLower() -ne "y") {Write-Host "Skiping..." return}
    $defaultPolicyName = "Default Domain Policy"
    if (!($policyName = Read-Host "GPO Name [$defaultPolicyName]")) { $policyName = $defaultPolicyName }
    $gpo = Get-GPO -Name $policyName
    if (!$gpo){
        Write-Error "GPO not found"
        Exit 1
    }
    $GpoGuid = $gpo.id.Guid

    try{
        $Certificate = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($CertFilePath)
        $certPoliciesRegistryKey = "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\SystemCertificates\Root\Certificates\$($Certificate.Thumbprint)"
        $tempRegistryKey = "HKLM:\Software\Microsoft\SystemCertificates\Temp\Certificates\$($Certificate.Thumbprint)"
        Write-Debug "Certificate thumbprint $($Certificate.Thumbprint)"
        
        try{
            if (!(Test-Path "CERT:\LocalMachines\Temp")) {
                Write-Host "Creating temp certificate store"
                New-Item -Path "CERT:\LocalMachine\Temp" -ErrorAction Stop | Out-Null
                $deleteStore=$true
            }
        }catch{
            Write-Error 'Error creating a key store "Temp", perhaps it`s already exsits. Run "certmgr" to list key stores'
            Write-Error $_.Exception
            Exit 1
        }
        Import-Certificate $CertFilePath -CertStoreLocation "CERT:\LocalMachine\Temp" 
        $importKeyValue = (Get-ItemProperty -Path $tempRegistryKey).Blob

        if ($deleteStore){
            Write-Host "Removing temp certificate store"
            Remove-Item -Path "CERT:\LocalMachine\Temp" -ErrorAction Stop -Recurse -Force -Confirm:$false | Out-Null
        }

        Write-Debug "Import GPO Path: $certPoliciesRegistryKey"
        if (!(Get-GPRegistryValue -Guid $GpoGuid -Key $certPoliciesRegistryKey -ErrorAction silentlycontinue)) {
            Set-GPRegistryValue -Guid $GpoGuid -Key $certPoliciesRegistryKey -ValueName 'Blob' -Type Binary -Value $importKeyValue 
         }else{
             Write-Host "Certificate already exists in Trusted Root CA store"
         }
        gpupdate /force
    }catch{
        Write-Error $_.Exception
        Exit 1
    }
}

function getBasueUrlFromToken {
    $tokenPayload = (ConvertFrom-SecureString -AsPlainText -SecureString $global:accessToken).Split(".")[1].Replace('-', '+').Replace('_', '/')
    while ($tokenPayload.Length % 4) { $tokenPayload += "=" }
    $tokenByteArray = [System.Convert]::FromBase64String($tokenPayload)
    $tokenArray = [System.Text.Encoding]::ASCII.GetString($tokenByteArray)
    $tokobj = $tokenArray | ConvertFrom-Json
    Write-Debug "Base URL: $($tokobj.aud[0])"    
    return "$($tokobj.aud[0])/v1"
}

if ($args[0] -eq "-Debug"){$DebugPreference = "Continue"; Write-Debug "Debug On"}
Run
if ($args[0] -eq "-Debug"){$DebugPreference = "SilentlyContinue"}




