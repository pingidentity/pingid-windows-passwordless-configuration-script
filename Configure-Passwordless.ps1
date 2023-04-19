#Execution Order
#1. Run validations - admin rights and AD module
#2. Select PingOne Environment
#3. Create CA certificate, install to NTAuth store, install to Trusted Root store in GPO
#4. Set unique user attribute
#5. Create SOP, use The created flow
#6. Create an Application, use the created SOP and CA certificate
#7. Issue a KDC certificate and install it in the Personal store

Set-StrictMode -Version Latest

$apiEnviornements="environments"
$apiKeys="keys"
$apiSchemas="schemas"
$apiSignOnPolicies="signOnPolicies"
$apiApplications="applications"
$date=Get-Date -UFormat "%m-%d-%Y"
$datetime=Get-Date -UFormat "%y%m%d%H%M%S"
$defaultAccountName = 'PingIDSvcACC'
$defaultGroupName = 'PingIDSvcGR'
$sourceTemplateName = "SmartcardLogon"
$defaultTemplateName = "PingIDLogon"

$global:IssuanceCertId = $null

function RunValidations{
    if ($PSVersionTable.PSVersion.Major -lt 7) {
        Write-Error "PowerShell 7 and above is required"
        Exit 1
    }

    $currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    if(!$currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)){
        Write-Error "Missing administrative rights, can not execute"
        Exit 1
    }

    $checkAD=Get-Service 'Active Directory Domain Services'
    if ($checkAD.Status -ne 'Running'){
        Write-Error "Active Directory Domain Services not running"
        Exit 1
    }

	$checkKDC=Get-Service 'Kerberos Key Distribution Center'
    if ($checkKDC.Status -ne 'Running'){
        Write-Error "Kerberos Key Distribution Center not running"
        Exit 1
    }
}

function Run{
    Write-Host "Welcome to PingID Windows Passwordless configuration wizard`n"

    RunValidations
    if (!$global:accessToken){
        $global:accessToken =  Read-Host  "Enter PingOne access token" | ConvertTo-SecureString -AsPlainText
    }else{
        $global:accessToken =  $global:accessToken | ConvertTo-SecureString -AsPlainText
    }

    $global:apiBase=getBaseUrlFromToken

    ############Read Env
    selectEnv
    Write-Host "`nSelected enviornment: " $global:envId " " $global:envName

    $caType = $host.UI.PromptForChoice(
        "What Certification Authority do you wish to use?",
        "Enter your choice",
            [System.Management.Automation.Host.ChoiceDescription[]](
                (New-Object System.Management.Automation.Host.ChoiceDescription "&PingOne","Use PingOne CA"),
                (New-Object System.Management.Automation.Host.ChoiceDescription "&Microsoft","Use Microsoft CA")
            ),
            -1)

    if ($caType -eq 0) {
        ############Create CA
        Write-Host "`nCreating an issuance (CA) certificate"
        createCACertificate
    } else {
        if (-not(Get-Command "Add-CATemplate" -errorAction SilentlyContinue)) {
            Write-Host "`nADCSAdministration module not found"
            Exit 1
        }

        $KdsKeyPresent = Get-KdsRootKey -ErrorAction SilentlyContinue
        if (-not $KdsKeyPresent) {
            Write-Host "`nKDS Root Key doesn't exist, creating one"
            Add-KdsRootKey -EffectiveTime ((get-date).addhours(-10))
            Exit 1
        }
    }

    ############Make External ID Unique
    Write-Host "`nSetting ExternalID Attribute as Unique"
    setUniqueDirectoryAttribute

    ############Create SOP
    Write-Host "`nCreating Signon Policy"
    createSop

    ############Create Application
    Write-Host "`nCreating OIDC Application"
    createApp

    if ($caType -eq 0) {
        ###########Create KDC Cert
        Write-Host "`nCreating KDC certificate"
        kdcCert
    }

    ###########Create ServiceAccount
    Write-Host "`nCreating Service Account"
    $ServiceAccount = New-ServiceAccount

    $TemplateName = $null
    $ServiceAccountName = $null
    if ($caType -eq 1) {
        ###########Create CA Template
        Write-Host "`nCreating CA Template"
        $TemplateName, $ServiceAccountName = New-Template -ServiceAccount $ServiceAccount
    }

    gpupdate /force
    Write-Host "`n`n`n`n`n"

    Write-Host "To install PingID Windows Login Passwordless on the client machine, run the installer with the following flags:"

    $OIDCDiscoveryEndPoint = $global:baseUrl + "/.well-known/openid-configuration"

    $ServiceAccountName ??= ($ServiceAccount ? $ServiceAccount.SamAccountName : $null)

    Write-Host "/OIDCDiscoveryEndpoint=$OIDCDiscoveryEndPoint"
    Write-Host " /OIDCClientID=$global:AppId"
    Write-Host " /OIDCSecret=$global:AppSecret"
    Write-Host " /CAType=$(($caType -eq 0) ? 'PINGONE' : 'MICROSOFT')"
    if ($ServiceAccountName) {
        Write-Host " /ServiceAccount=$ServiceAccountName"
    }
    if ($caType -eq 1 -and $TemplateName) {
	Write-Host " /CATemplate=$TemplateName"
    }

    Write-Host "for additional information, see: https://docs.pingidentity.com/bundle/pingid/page/lkz1629022490771.html"
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
    $caCertC = Read-Host "Country (2 letter code) []"
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
    Invoke-Api -Method 'GET' -Endpoint $apiKeys -ResourceId $cert.id -AsPem $true -OutFile "$caCertCN.cer"
    $certFileName = "$(Get-Location)\$caCertCN.cer"
    Write-Host "Done $certFileName"

    if ((Read-Host "Do you wish to propagate the CA certificate to Enterprise NTAuth store? (y/n) [n]").ToLower() -ne "y")
    {
        Write-Host "Skiping..."
        return
    }
    Write-Host "Installing certificate to Enterprise NTAuth store..."
    Write-Host 'certutil -dspublish -f "'$caCertCN'.cer" NTAuthCA'
    $error.Clear()
    certutil -dspublish -f "$caCertCN.cer" NTAuthCA
    write-debug "ExitCode: $lastExitCode"
    if ($lastExitCode -ne 0) {
         Write-Error "Failed To Execute Command: "
         Exit $lastExitCode
    }

    Write-Host "`n`n`n`n`n"

    installCACertGpo -CertFilePath $certFileName
}

function setUniqueDirectoryAttribute{
    $defaultAttributeName="externalId"
    if (!($global:attributeName = Read-Host "Common Name [$defaultAttributeName]")) { $global:attributeName = $defaultAttributeName }

    $schemas=Invoke-API -Method 'GET' -Endpoint $apiSchemas
    $attributes=Invoke-API -Method 'GET' -Url $schemas._embedded.schemas._links.attributes.href
    $attributes._embedded.attributes  | Foreach-Object -Process{
        if ($_.name -eq "$global:attributeName"){
            $link= $_._links.self.href
        }
    }
    $request=@{
        "type" = "STRING"
        "unique" = $true
        "enabled" = $true
    }
    Invoke-API -Method 'PATCH' -Url $link -Body $request

}


function createSop{
    $sopReq = ConvertFrom-Json -InputObject '{"default":false,"name":"Windows_Passwordless_auto_generatd_","environmentId":null}'
    $actionsReqJson = '
    {
        "priority":1,
        "type":"PINGID_WINLOGIN_PASSWORDLESS_AUTHENTICATION",
        "offlineMode": {
            "enabled": true
        },
        "uniqueUserAttribute": {
            "name": "' + $global:attributeName + '"
        }
    }'
    $actionsReq = ConvertFrom-Json -InputObject $actionsReqJson
    $sopReq.name += $date

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
            "winlogin.pingone.com://callbackauth"
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
    if ((Read-Host "Do you wish to continue execution of this step? (y/n) [n]").ToLower() -ne "y") {
	    Write-Host "Skiping..."
	    return
    }
    $dnsName=[System.Net.DNS]::GetHostByName($Null).hostname
    $config='
        [newrequest]
        subject = "CN='+$dnsName+'"
        KeyLength = 2048
        MachineKeySet = TRUE
        Exportable = FALSE
        RequestType = PKCS10
        SuppressDefaults = TRUE
	HashAlgorithm = SHA256
        [Extensions]
        ;Note 2.5.29.17 is the OID for a SAN extension.
        2.5.29.17 = "{text}"
        _continue_ = "dns='+$dnsName+'&"'
    $config | Out-File -FilePath $env:TEMP\config.temp.inf
	$kdcRequsetFile="kdc_" + $datetime + ".req"
	$kdcCertFile=$env:TEMP + "\kdc_" + $datetime + ".cer"
    Write-Host "Creating certificate request: $kdcRequsetFileName"
    certreq -new $env:TEMP\config.temp.inf $kdcRequsetFile
    if ($lastExitCode -ne 0) {
         Write-Error "Failed To Execute Command: "
         Exit $lastExitCode
    }

    Write-Host "Issuing certificate from the request, using issuace certificate ID: $global:IssuanceCertId"
    Invoke-MultipartFormDataUpload -Uri $global:appLink'/kdcCSR?validityDuration=31536000' -InFile $kdcRequsetFile -OutFile $kdcCertFile

    Write-Host 'Installing certificate to Local Macine, "Personal" key storage'
    certreq -accept -machine -f $kdcCertFile
    if ($lastExitCode -ne 0) {
        Write-Error "Failed To Execute Command: "
        Exit $lastExitCode
    }
}

function IsUniqueOID {
    param(
        [Parameter(Mandatory=$true)]
        $TemplateOID,
        [Parameter(Mandatory=$true)]
        $ConfigNC
    )
    $Search = Get-ADObject `
        -SearchBase "CN=OID,CN=Public Key Services,CN=Services,$ConfigNC" `
        -Filter "msPKI-Cert-Template-OID -eq '$TemplateOID'" `
        -SearchScope Subtree
    if ($Search) {$False} else {$True}
}

function New-TemplateOID {
    param(
        [Parameter(Mandatory=$true)]
        $ConfigNC
    )
    do {
        $OID_Part_1 = Get-Random -Minimum 10000000 -Maximum 99999999
        $OID_Part_2 = Get-Random -Minimum 10000000 -Maximum 99999999
        $OID_Forest = Get-ADObject `
            -Identity "CN=OID,CN=Public Key Services,CN=Services,$ConfigNC" `
            -Properties msPKI-Cert-Template-OID |
            Select-Object -ExpandProperty msPKI-Cert-Template-OID

        $msPKICertTemplateOID = "$OID_Forest.$OID_Part_1.$OID_Part_2"
    } until (IsUniqueOID -TemplateOID $msPKICertTemplateOID -ConfigNC $ConfigNC)

    return $msPKICertTemplateOID
}

function New-Template {
    param( [Object]$ServiceAccount )
    do {
        $response = Read-Host -Prompt "Do you wish to continue execution of this step? (y/n) [n]"
        if (-not $response -or $response -eq "n") {
            Write-Host "Skiping..."
            return $null, $null
        }
    } until ($response -eq 'y')

    if ($null -eq $ServiceAccount) {
        $ServiceAccountName = Read-Host -Prompt "Service Account name [$defaultAccountName]"
        if ([string]::IsNullOrWhiteSpace($ServiceAccountName)) {
            $ServiceAccountName = $defaultAccountName
        }
        $ServiceAccount = Get-ADServiceAccount -Filter "Name -eq '$ServiceAccountName'";
    }

    $TemplateName = Read-Host -Prompt "CA template name [$defaultTemplateName]"
    if ([string]::IsNullOrWhiteSpace($TemplateName)) {
        $TemplateName = $defaultTemplateName
    }

    $ConfigContext = ([ADSI]"LDAP://RootDSE").ConfigurationNamingContext
    $ADSI = [ADSI]"LDAP://CN=Certificate Templates,CN=Public Key Services,CN=Services,$ConfigContext"

    $existingTemplate = $ADSI.psbase.children | Where-Object {$_.Name -eq $TemplateName}
    if ($null -ne $existingTemplate) {
        Write-Host "Template with $TemplateName already exist"
	return $TemplateName, $ServiceAccount.SamAccountName
    }

    $SrcTempl = $ADSI.psbase.children | Where-Object {$_.Name -eq $SourceTemplateName}

    $NewTempl = $ADSI.Create("pKICertificateTemplate", "CN=$TemplateName")
    $NewTempl.Put('distinguishedName', "CN=$TemplateName,CN=Certificate Templates,CN=Public Key Services,CN=Services,$ConfigContext") | Out-Null
    $NewTempl.Put('displayName', $TemplateName) | Out-Null
    $NewTempl.SetInfo() | Out-Null

    $NewTempl.flags = "131584"
    $NewTempl.revision = "100"
    $NewTempl.Put('pKIDefaultKeySpec', $SrcTempl.pKIDefaultKeySpec.ToString()) | Out-Null
    $NewTempl.'msPKI-Template-Schema-Version' = "2"
    $NewTempl.'msPKI-Template-Minor-Revision' = "3"
    $NewTempl.pKIMaxIssuingDepth = $SrcTempl.pKIMaxIssuingDepth
    $NewTempl.pKICriticalExtensions.AddRange($SrcTempl.pKICriticalExtensions) | Out-Null
    $NewTempl.pKICriticalExtensions.Add("2.5.29.7") | Out-Null
    $NewTempl.pKIExtendedKeyUsage = $SrcTempl.pKIExtendedKeyUsage
    $NewTempl.'msPKI-RA-Signature' = $SrcTempl.'msPKI-RA-Signature'
    $NewTempl.'msPKI-Enrollment-Flag' = $SrcTempl.'msPKI-Enrollment-Flag'
    $NewTempl.'msPKI-Private-Key-Flag' = $SrcTempl.'msPKI-Private-Key-Flag'
    $NewTempl.'msPKI-Certificate-Name-Flag' = $SrcTempl.'msPKI-Certificate-Name-Flag'
    $NewTempl.'msPKI-Minimal-Key-Size' = $SrcTempl.'msPKI-Minimal-Key-Size'
    $NewTempl.'msPKI-Cert-Template-OID' = New-TemplateOID -ConfigNC $ConfigContext
    $NewTempl.Put('msPKI-Certificate-Application-Policy', @("1.3.6.1.5.5.7.3.2", "1.3.6.1.4.1.311.20.2.2")) | Out-Null

    $NewTempl.pKIKeyUsage = $SrcTempl.pKIKeyUsage
    $NewTempl.pKIExpirationPeriod = $SrcTempl.pKIExpirationPeriod
    $NewTempl.pKIOverlapPeriod = $SrcTempl.pKIOverlapPeriod
    $NewTempl.SetInfo() | Out-Null

    $Rule = New-Object System.DirectoryServices.ActiveDirectoryAccessRule( `
        (New-Object System.Security.Principal.SecurityIdentifier $ServiceAccount.SID), `
        [System.DirectoryServices.ActiveDirectoryRights]"WriteProperty, GenericRead, WriteDacl, WriteOwner, ExtendedRight", `
        [System.Security.AccessControl.AccessControlType]"Allow");
    $NewTempl.ObjectSecurity.SetAccessRule($Rule)
    $NewTempl.CommitChanges();

    # Add the certificate template to the certificate authority
    $p = Start-Process "C:\Windows\System32\certtmpl.msc" -PassThru
    Start-Sleep 2
    $p | Stop-Process
    Add-CATemplate -Name $TemplateName -Force
    return $TemplateName, $ServiceAccount.SamAccountName
}

function New-ServiceAccount {
    param ([string]$GroupName)
    do {
        $response = Read-Host -Prompt "Do you wish to continue execution of this step? (y/n) [n]"
        if (-not $response -or $response -eq "n") {
            Write-Host "Skiping..."
            return
        }
    } until ($response -eq 'y')

    $GroupName = Read-Host -Prompt "Security Group name [$defaultGroupName]"
    if ([string]::IsNullOrWhiteSpace($GroupName)) {
        $GroupName = $defaultGroupName
    }

    if (Get-ADGroup -Filter "Name -eq '$GroupName'") {
        Write-Host "Security Group $GroupName already exists";
    } else {
        Write-Host "Creating Security Group $GroupName";
        $Group = New-ADGroup $GroupName -GroupScope Global -PassThru -Description "Computers that uses PingID passwordless"
        if ($Group) {
            Write-Host "Adding Domain Computers to the group"
            Add-AdGroupMember -Identity $GroupName -Members "Domain Computers"
        }
    }

    $AccountName = Read-Host -Prompt "Service Account name [$defaultAccountName]"
    if ([string]::IsNullOrWhiteSpace($AccountName)) {
        $AccountName = $defaultAccountName
    }

    $ServiceAccount = Get-ADServiceAccount -Filter "Name -eq '$AccountName'"
    if ($ServiceAccount) {
        Write-Host "Managed Service Account $AccountName alredy exists";
    } else {
        Write-Host "Creating $AccountName"
        $ServiceAccount = New-ADServiceAccount -name $AccountName -dnshostname $env:computername -PrincipalsAllowedToRetrieveManagedPassword $GroupName -PassThru
        Write-Host "Adding the service account to the computer"
        Add-ADComputerServiceAccount -Identity $env:computername -ServiceAccount $AccountName
    }
    return $ServiceAccount
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
    if ((Read-Host "Do you wish to continue execution this step? (y/n) [n]").ToLower() -ne "y") {
	    Write-Host "Skiping..."
	    return
    }
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
    }catch{
        Write-Error $_.Exception
        Exit 1
    }
}

function getBaseUrlFromToken {
    $tokenPayload = (ConvertFrom-SecureString -AsPlainText -SecureString $global:accessToken).Split(".")[1].Replace('-', '+').Replace('_', '/')
    while ($tokenPayload.Length % 4) { $tokenPayload += "=" }
    $tokenByteArray = [System.Convert]::FromBase64String($tokenPayload)
    $tokenArray = [System.Text.Encoding]::ASCII.GetString($tokenByteArray)
    $tokobj = $tokenArray | ConvertFrom-Json
	$global:baseUrl= $tokobj.iss
    Write-Debug "Base URL: $($tokobj.aud[0])"
    return "$($tokobj.aud[0])/v1"
}

if (($args.length > 0) -and ($args[0] -eq "-Debug")) { $DebugPreference = "Continue"; Write-Debug "Debug On" }
Run
if (($args.length > 0) -and ($args[0] -eq "-Debug")) { $DebugPreference = "SilentlyContinue" }
