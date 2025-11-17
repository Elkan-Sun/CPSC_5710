# ----------------------------------------------
# 1. Create a fake file that contains a hard-coded fake token
# ----------------------------------------------

$fakePath = "$env:TEMP\faketoken.txt"

$fakeToken = "FAKE_TOKEN_1234567890.ABCDEFGHIJKLMNOPQRSTUVWXYZ"

Set-Content -Path $fakePath -Value @"
User: exampleUser
Token: $fakeToken
Note: This is a fake educational token, not a real one.
"@

Write-Output "Created fake token file at:"
Write-Output "  $fakePath"
Write-Output ""

# ----------------------------------------------
# 2. Define a regex pattern that LOOKS LIKE a Discord token
#    but is safe (no real tokens)
# ----------------------------------------------

$discordPattern = "[A-Za-z0-9_\-]{10,}"

Write-Output "Searching for hard-coded token patterns..."
Write-Output ""

# ----------------------------------------------
# 3. Search the fake file
# ----------------------------------------------

try {
    $content = Get-Content -Path $fakePath -Raw

    $matches = [regex]::Matches($content, $discordPattern)

    if ($matches.Count -gt 0) {
        Write-Output "FOUND TOKEN-LIKE STRINGS:"
        foreach ($m in $matches) {
            Write-Output "  -> $m"
        }
    }
    else {
        Write-Output "No token-like strings found."
    }
}
catch {
    Write-Output "Error reading fake file. (Still safe!)"
}

Write-Output ""
Write-Output "=============================================="
Write-Output " DEMO COMPLETE — NO REAL TOKENS WERE TOUCHED "
Write-Output "=============================================="
