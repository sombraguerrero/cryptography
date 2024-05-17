param(
    [switch]$decrypt
)
Write-Host "This script performs the same character substitutions on Base64 strings as Python's URL-safe encoding and decoding!"
$x = Read-Host -Prompt "Enter a string"
if ($decrypt)
{
    $raw = $x.Replace('-','+').Replace('_','/')
    $bytes = [System.Convert]::FromBase64String($raw)
    $msg = [System.Text.Encoding]::UTF8.GetString($bytes)
    Write-Host $msg
}
else
{
    $raw = [System.Text.Encoding]::UTF8.GetBytes($x)
    $str = [System.Convert]::ToBase64String($raw)
    $msg = $str.Replace('+','-').Replace('/','_')
    Write-Host $msg
}