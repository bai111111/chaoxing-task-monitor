# auth.ps1 - 学习通账密保存/读取
# 密码用 Windows DPAPI(CurrentUser 范围)加密:只有当前 Windows 用户在本机可解密。
# 用法:
#   save: powershell.exe -NoProfile -ExecutionPolicy Bypass -File auth.ps1 -Mode save -Phone <手机号> -Password <密码>
#   read: powershell.exe -NoProfile -ExecutionPolicy Bypass -File auth.ps1 -Mode read
param(
  [Parameter(Mandatory = $true)][ValidateSet("save", "read")][string]$Mode,
  [string]$Phone,
  [string]$Password
)

$ErrorActionPreference = "Stop"
Add-Type -AssemblyName System.Security
$dir = Join-Path $env:USERPROFILE ".chaoxing"
$file = Join-Path $dir "auth.json"

function Protect-Text([string]$plain) {
  $bytes = [System.Text.Encoding]::UTF8.GetBytes($plain)
  [System.Convert]::ToBase64String(
    [System.Security.Cryptography.ProtectedData]::Protect(
      $bytes, $null, [System.Security.Cryptography.DataProtectionScope]::CurrentUser))
}

function Unprotect-Text([string]$b64) {
  $bytes = [System.Convert]::FromBase64String($b64)
  [System.Text.Encoding]::UTF8.GetString(
    [System.Security.Cryptography.ProtectedData]::Unprotect(
      $bytes, $null, [System.Security.Cryptography.DataProtectionScope]::CurrentUser))
}

switch ($Mode) {
  "save" {
    if (-not $Phone -or -not $Password) { throw "save 模式需要 -Phone 和 -Password" }
    if (-not (Test-Path $dir)) { New-Item -ItemType Directory -Path $dir | Out-Null }
    $json = [ordered]@{
      scheme      = "dpapi-currentuser-v1"
      phone       = $Phone
      passwordEnc = Protect-Text $Password
      updatedAt   = (Get-Date).ToString("s")
    } | ConvertTo-Json
    Set-Content -Path $file -Value $json -Encoding UTF8
    Write-Output "saved: $file"
  }
  "read" {
    if (-not (Test-Path $file)) { throw "未找到 $file" }
    $data = Get-Content -Path $file -Raw | ConvertFrom-Json
    if ($data.scheme -ne "dpapi-currentuser-v1") {
      throw "auth.json 不是加密格式(scheme=$($data.scheme)),请先用 save 模式迁移"
    }
    @{ phone = $data.phone; password = (Unprotect-Text $data.passwordEnc) } | ConvertTo-Json -Compress
  }
}
