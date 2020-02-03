# Input bindings are passed in via param block.
param($Timer)

# Get the current universal time in the default string format
$currentUTCtime = (Get-Date).ToUniversalTime()

# The 'IsPastDue' porperty is 'true' when the current function invocation is later than scheduled.
if ($Timer.IsPastDue) {
    Write-Host "PowerShell timer is running late!"
}

# Write an information log with the current time.
Write-Host "PowerShell timer trigger function ran! TIME: $currentUTCtime"

#Setup required variables
$baseUrl = "https://us-api.mimecast.com"
$uri = "/api/ttp/url/get-logs"
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

# From Date Time minus one day of execution runtime
$fromdatetime = (Get-Date).AddDays(-1).ToString('yyyy-MM-ddThh:mm:ss+0000')

# To Date Time of execution runtime | these two varibales that will pass create a window for a day back of results
$todatetime = Get-Date -Format "yyyy-MM-ddThh:mm:ss+0000"

#                          ""pageToken"": ""ENTER PAGE TOKEN HERE OR REMOVE FIELD""

#Create post body
$postBody = "{
                 ""meta"": {
                     ""pagination"": {
                         ""pageSize"": 25
                     }
                 },
                 ""data"": [
                     {
                         ""oldestFirst"": False,
                         ""from"": ""$fromdatetime"",
                         ""route"": ""all"",
                         ""to"": ""$todatetime"",
                         ""scanResult"": ""all""
                     }
                 ]
                }"
 
#Send Request
$response = Invoke-RestMethod -Method Post -Headers $headers -Body $postBody -Uri $url -ResponseHeadersVariable "headvar"
 
#Print the response
$response

#Print hte Headers
$headvar

#Send Response to LogAnalytics
# Specify the name of the record type that you'll be creating
$LogType = "TTPurl"

# You can use an optional field to specify the timestamp from the data. If the time field is not specified, Azure Monitor assumes the time is the message ingestion time
$TimeStampField = "date"

<# Create two records with the same set of properties to create
$json = @"
[{  "StringValue": "MyString1",
    "NumberValue": 42,
    "BooleanValue": true,
    "DateValue": "2019-09-12T20:00:00.625Z",
    "GUIDValue": "9909ED01-A74C-4874-8ABF-D2678E3AE23D"
},
{   "StringValue": "MyString2",
    "NumberValue": 43,
    "BooleanValue": false,
    "DateValue": "2019-09-12T20:00:00.625Z",
    "GUIDValue": "8809ED01-A74C-4874-8ABF-D2678E3AE23D"
}]
"@ #>

# Needs Rework to further parse before submitting
$mimecast = $response | ConvertTo-Json

#Parse json data removing a nest for clean push to log Analytics
$mimecastrefine = $mimecast | ConvertFrom-Json
$mimecastrefine = $mimecastrefine.data | ConvertTo-Json

# Create the function to create the authorization signature
Function Build-Signature ($customerId, $sharedKey, $date, $contentLength, $method, $contentType, $resource)
{
    $xHeaders = "x-ms-date:" + $date
    $stringToHash = $method + "`n" + $contentLength + "`n" + $contentType + "`n" + $xHeaders + "`n" + $resource

    $bytesToHash = [Text.Encoding]::UTF8.GetBytes($stringToHash)
    $keyBytes = [Convert]::FromBase64String($sharedKey)

    $sha256 = New-Object System.Security.Cryptography.HMACSHA256
    $sha256.Key = $keyBytes
    $calculatedHash = $sha256.ComputeHash($bytesToHash)
    $encodedHash = [Convert]::ToBase64String($calculatedHash)
    $authorization = 'SharedKey {0}:{1}' -f $customerId,$encodedHash
    return $authorization
}

# Create the function to create and post the request
Function Post-LogAnalyticsData($customerId, $sharedKey, $body, $logType)
{
    $method = "POST"
    $contentType = "application/json"
    $resource = "/api/logs"
    $rfc1123date = [DateTime]::UtcNow.ToString("r")
    $contentLength = $body.Length
    $signature = Build-Signature `
        -customerId $customerId `
        -sharedKey $sharedKey `
        -date $rfc1123date `
        -contentLength $contentLength `
        -method $method `
        -contentType $contentType `
        -resource $resource
    $uri = "https://" + $customerId + ".ods.opinsights.azure.com" + $resource + "?api-version=2016-04-01"

    $headers = @{
        "Authorization" = $signature;
        "Log-Type" = $logType;
        "x-ms-date" = $rfc1123date;
        "time-generated-field" = $TimeStampField;
    }

    $response = Invoke-WebRequest -Uri $uri -Method $method -ContentType $contentType -Headers $headers -Body $body -UseBasicParsing
    return $response.StatusCode

}

#VERIFY $RESPONSE

# Submit the data to the API endpoint
Post-LogAnalyticsData -customerId $customerId -sharedKey $sharedKey -body ([System.Text.Encoding]::UTF8.GetBytes($mimecastrefine)) -logType $logType
