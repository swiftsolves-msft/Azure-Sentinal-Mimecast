#Setup required variables
$baseUrl = "https://us-api.mimecast.com"
$uri = "/api/audit/get-siem-logs"
$url = $baseUrl + $uri
# Mimecast API Applications AccessKey generated
$accessKey = ""
# Mimecast API Applications SecertKey generated
$secretKey = ""
# Mimecast API Applications ID
$appId = ""
# Mimecast API Applications Key
$appKey = ""
# Replace with your Azure Function Resource Group Name
$funcrgname = ""
# Replace with your Azure Function Name
$funcname = ""
# Replace with your Workspace ID
$CustomerId = "" 
# Replace with your Primary Key
$SharedKey = ""


#Generate request header values
$hdrDate = (Get-Date).ToUniversalTime().ToString("ddd, dd MMM yyyy HH:mm:ss UTC")
$requestId = [guid]::NewGuid().guid

#Create the HMAC SHA1 of the Base64 decoded secret key for the Authorization header
$sha = New-Object System.Security.Cryptography.HMACSHA1
$sha.key = [Convert]::FromBase64String($secretKey)
$sig = $sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($hdrDate + ":" + $requestId + ":" + $uri + ":" + $appKey))
$sig = [Convert]::ToBase64String($sig)

#Create Headers
$headers = @{"Authorization" = "MC " + $accessKey + ":" + $sig;
                "x-mc-date" = $hdrDate;
                "x-mc-app-id" = $appId;
                "x-mc-req-id" = $requestId;
                "Content-Type" = "application/json"}

#Create post body
#""token"": ""value of previous mc-siem-token response header"", WAS LINE 34. TOKEN FIELD MUST BE ADDED AFTER FIRST RUN 
$postBody = "{
                 ""data"":[
                        {
                            ""type"": ""MTA"",
                            ""fileFormat"": ""json""
                        }
                    ]
                }"

                
#Send Request
$response = Invoke-RestMethod -Method Post -Headers $headers -Body $postBody -Uri $url -ResponseHeadersVariable "headvar"
$mcsiemtoken = $headVar.'mc-siem-token'
Write-Host $mcsiemtoken
# Convert stringarray() to string
$newmcsiemtoken = $newmcsiemtoken | Out-String

# Create a App Settings hash table
$newappsets = $null
$newappsets = @{}

#before exiting write new MC SIEM Token to overwrite env variable: $newmcsiemtoken to $ENV:mcsiemtoken
#Obtain Existing App Settings Hashtbale

$app = Get-AzWebApp -ResourceGroupName $funcrgname -Name $funcname
$appsets = $app.SiteConfig.AppSettings

#Run through and populate the new App Settings Hashtable with existing data except the mcsiemtoken, this will be replaced by new value.
foreach ($appset in $appsets){
    # Check if key/value is mcsiemtoken, overwrite a new value
    if ($appset.Name -eq "mcsiemtoken"){
        $newappsets.Add( $appset.Name, $newmcsiemtoken )
    }
    # place in existing app settings
    Else {
        $newappsets.Add( $appset.Name, $appset.Value )
    }
}

#overwrite the web app settings with new app settings hashtable with new mcsiemtoken
Set-AzWebApp -ResourceGroupName $funcrgname -Name $funcname -AppSettings $newappsets
