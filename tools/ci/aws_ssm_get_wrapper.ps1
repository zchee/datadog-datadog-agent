param (
    [string]$parameterName
    [string]$environmentName
)

$retryCount = 0
$maxRetries = 10

while ($retryCount -lt $maxRetries) {
    $result = (aws ssm get-parameter --region us-east-1 --name $parameterName --with-decryption --query "Parameter.Value" --output text 2> awsErrorFile.txt)
    $error = Get-Content awsErrorFile.txt
    if ($result) {
        Set-Variable -Name $environmentName -Value $result
        break
    }
    if ($error -match "Unable to locate credentials") {
        # See 5th row in https://docs.google.com/spreadsheets/d/1JvdN0N-RdNEeOJKmW_ByjBsr726E3ZocCKU8QoYchAc
        Write-Host "Credentials won't be retrieved, break the loop and ask Gitlab to retry"
        exit 42
    }

    $retryCount++
    Start-Sleep -Seconds ([math]::Pow(2, $retryCount))
}
