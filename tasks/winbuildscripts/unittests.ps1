$ErrorActionPreference = "Continue"
$Password = ConvertTo-SecureString "dummyPW_:-gch6Rejae9" -AsPlainText -Force
New-LocalUser -Name "ddagentuser" -Description "Test user for the secrets feature on windows." -Password $Password

$Env:Python2_ROOT_DIR=$Env:TEST_EMBEDDED_PY2
$Env:Python3_ROOT_DIR=$Env:TEST_EMBEDDED_PY3

py.exe -c 'import shutil; print(shutil.which("vault"))'
py.exe -c 'import shutil; print(shutil.which("vault.exe"))'
ls "c:\devtools"
ls "c:\devtools\vault"
$result=(vault kv get -field="app_id" kv/k8s/gitlab-runner/datadog-agent/"agent-github-app")
Write-Host "Result: $result"