# Generate 2MB text file
$text = "Lorem ipsum dolor sit amet, consectetur adipiscing elit. Sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat. Duis aute irure dolor in reprehenderit in voluptate velit esse cillum dolore eu fugiat nulla pariatur. Excepteur sint occaecat cupidatat non proident, sunt in culpa qui officia deserunt mollit anim id est laborum. "

$targetSize = 2 * 1024 * 1024  # 2 MB in bytes
$sb = New-Object System.Text.StringBuilder

# Keep appending text until we reach target size
while ($sb.Length -lt $targetSize) {
    $sb.Append($text) | Out-Null
}

# Trim to exact size
$finalText = $sb.ToString().Substring(0, $targetSize)

# Write to file
$outputPath = "c:\Users\USER\OneDrive\Desktop\Networking Project1\2mb_test_text.txt"
[System.IO.File]::WriteAllText($outputPath, $finalText, [System.Text.Encoding]::UTF8)

# Display file info
$fileInfo = Get-Item $outputPath
Write-Host "Created 2MB text file successfully"
Write-Host "File: $($fileInfo.FullName)"
Write-Host "Size: $($fileInfo.Length) bytes"
Write-Host "Size: $([math]::Round($fileInfo.Length/1MB, 2)) MB"
