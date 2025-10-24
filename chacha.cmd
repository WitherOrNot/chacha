@echo off

cd "%~dp0"
powershell "$f=[System.IO.File]::ReadAllText('%~f0') -split ':chacha\:.*';. ([scriptblock]::Create($f[1]))"

pause
exit 

:chacha:
$ErrorActionPreference = "Stop"

function Get-IID {
    param (
        [string] $PKey,
        [string] $PKeyConfig,
        [UInt64] $HWID
    )
        
    $IID = ""
    $Edition = ""
    $Channel = ""
    $Partnum = ""
    $t = [AppDomain]::CurrentDomain.DefineDynamicAssembly((Get-Random), 1).DefineDynamicModule((Get-Random), $False).DefineType((Get-Random))
    $t.DefinePInvokeMethod('GetPKeyData', 'pidgenx.dll', 22, 1, [Int32], @([String], [String], [String], [UInt64], [UInt64], [String].MakeByRefType(), [String].MakeByRefType(), [String].MakeByRefType(), [String].MakeByRefType(), [IntPtr]), 1, 3).SetImplementationFlags(128)
    $pidgenx = $t.CreateType()
    $ret = $pidgenx::GetPKeyData($PKey, $PKeyConfig, $null, 0, $HWID, [ref]$IID, [ref]$Edition, [ref]$Channel, [ref]$Partnum, [IntPtr]::Zero)
    
    return $IID
}

function Get-CID {
    param (
        [string] $InstallationID
    )

    $MacKey = [byte[]](254,49,152,117,251,72,132,134,156,243,241,206,153,168,144,100,171,87,31,202,71,4,80,88,48,36,226,20,98,135,121,160,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0)[0..63]

    $xmlReq = "<ActivationRequest xmlns='http://www.microsoft.com/DRM/SL/BatchActivationRequest/1.0'><VersionNumber>2.0</VersionNumber><RequestType>1</RequestType><Requests><Request><PID>31337-42069-123-456789-04-1337-2600.0000-2542001</PID><IID>$InstallationID</IID></Request></Requests></ActivationRequest>"
    $bytes  = [Text.Encoding]::Unicode.GetBytes($xmlReq)
    $req64  = [Convert]::ToBase64String($bytes)
    $digest = [Convert]::ToBase64String(([Security.Cryptography.HMACSHA256]::new($MacKey)).ComputeHash($bytes))

    $soap = "<soap:Envelope xmlns:soap='http://schemas.xmlsoap.org/soap/envelope/'><soap:Body><BatchActivate xmlns='http://www.microsoft.com/BatchActivationService'><request><Digest>$digest</Digest><RequestXml>$req64</RequestXml></request></BatchActivate></soap:Body></soap:Envelope>"

    try {
        $resp = Invoke-RestMethod -Uri "https://activation.sls.microsoft.com/BatchActivation/BatchActivation.asmx" `
            -Method POST `
            -ContentType "text/xml; charset=utf-8" `
            -Headers @{SOAPAction="http://www.microsoft.com/BatchActivationService/BatchActivate"} `
            -Body $soap

        [xml]$x = $resp
        $node = $x.SelectSingleNode("//*[local-name()='ResponseXml']")
        if ($node) {
            [xml]$inner = ($node.InnerText -replace '&lt;','<' -replace '&gt;','>' -replace '&amp;','&')
            $cidNode = $inner.SelectSingleNode("//*[local-name()='CID']")
            $errNode = $inner.SelectSingleNode("//*[local-name()='ErrorCode']")
            if ($cidNode) {
                return $cidNode.InnerText
            } elseif ($errNode) {
                Write-Host "ErrorCode: $($errNode.InnerText)" -ForegroundColor Red
                $msg = $inner.SelectSingleNode("//*[local-name()='ErrorMessage']")
                if ($msg) { Write-Host "ErrorMessage: $($msg.InnerText)" -ForegroundColor Yellow }
            } else {
                Write-Host "No CID or ErrorCode found"; Write-Host $inner.OuterXml
            }
        } else {
            Write-Host "No ResponseXml in reply"
        }
    } catch {
        Write-Host "Request failed: $($_.Exception.Message)" -ForegroundColor Red
    }
}

$RootDNC = (Get-ADRootDSE).rootDomainNamingContext
$RootDNCBytes = [System.Text.Encoding]::Unicode.GetBytes($RootDNC)
$RootGUID = [System.Text.Encoding]::Unicode.GetBytes([System.BitConverter]::ToString((Get-ADObject -Identity $RootDNC).ObjectGUID.ToByteArray()).Replace("-", "").ToLower())
$ADHash = [Security.Cryptography.SHA256]::Create().ComputeHash($RootDNCBytes + $RootGUID)
$ADHWID = [UInt64][System.BitConverter]::ToUInt32($ADHash, 4) -shl 35 -bor (0x100000000 -bor [System.BitConverter]::ToUInt32($ADHash, 0))

$ADIID = Get-IID "NJCF7-PW8QT-3324D-688JX-2YV66" "$(Get-Location)\pkeyconfig.xrm-ms" $ADHWID
Write-Host "AD IID: $ADIID" -ForegroundColor Green
$ADCID = Get-CID $ADIID
Write-Host "AD CID: $ADCID" -ForegroundColor Green

$Iss = [System.IO.File]::ReadAllBytes("$env:SystemRoot\system32\spp\tokens\issuance\client-issuance-ul-oob.xrm-ms")
$PKC = [System.IO.File]::ReadAllBytes("$(Get-Location)\pkeyconfig.xrm-ms")
$Phn = [System.IO.File]::ReadAllBytes("$(Get-Location)\phone.xrm-ms")

New-ADObject -Name "01234-000-000000-0" -Type "msSPP-ActivationObject" -DisplayName "ADBA" -Path ("CN=Activation Objects,CN=Microsoft SPP,CN=Services,CN=Configuration," + $RootDNC) -OtherAttributes @{
    'msSPP-ConfigLicense'=$PKC;
    'msSPP-ConfirmationId'=$ADCID;
    'msSPP-CSVLKPartialProductKey'="XXXXX";
    'msSPP-CSVLKPid'="00000-01234-000-000000-03-1033-12345.0000-0012025";
    'msSPP-CSVLKSkuId'=[Guid]::Empty;
    'msSPP-InstallationId'=$ADIID;
    'msSPP-IssuanceLicense'=$Iss;
    'msSPP-KMSIds'=@(
        [Guid]"3c40b358-5948-45af-923b-53d21fcc7e79",
        [Guid]"8665cb71-468c-4aa3-a337-cb9bc9d5eaac",
        [Guid]"cb8fc780-2c05-495a-9710-85afffc904d7",
        [Guid]"8456efd3-0c04-4089-8740-5b7238535a65",
        [Guid]"58e2134f-8e11-4d17-9cb2-91069c151148",
        [Guid]"d27cd636-1962-44e9-8b4f-27b6c23efb85",
        [Guid]"969fe3c0-a3ec-491a-9f25-423605deb365",
        [Guid]"6e9fc069-257d-4bc4-b4a7-750514d32743",
        [Guid]"11b15659-e603-4cf1-9c1f-f0ec01b81888",
        [Guid]"8449b1fb-f0ea-497a-99ab-66ca96e9a0f5",
        [Guid]"b74263e4-0f92-46c6-bcf8-c11d5efe2959",
        [Guid]"3b576817-7b75-4362-9e13-223f2d9e9c97",
        [Guid]"907f1f65-adcd-4a2e-95bc-4bf500bc6e58",
        [Guid]"e85ee727-69c4-4528-99d2-216b0f065e38",
        [Guid]"a8973cb5-bf03-0a4c-9cef-703099645ab3",
        [Guid]"86d50b16-4808-41af-b83b-b338274318b2",
        [Guid]"617d9eb1-ef36-4f82-86e0-a65ae07b96c6",
        [Guid]"85b5f61b-320b-4be3-814a-b76b2bfafc82",
        [Guid]"e6a6f1bf-9d40-40c3-aa9f-c77ba21578c0",
        [Guid]"5f94a0bb-d5a0-4081-a685-5819418b2fe0",
        [Guid]"cbdcb1ba-e093-4c81-a463-10775291fdf9",
        [Guid]"7ba0bf23-d0f5-4072-91d9-d55af5a481b6",
        [Guid]"6d5f5270-31ac-433e-b90a-39892923c657"
    );
    'msSPP-PhoneLicense'=$Phn
}
Write-Host "ADBA Object successfully created." -ForegroundColor Green

:chacha:
