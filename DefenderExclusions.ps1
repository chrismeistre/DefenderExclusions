function DefenderEventsExclusions {
    $logName = "Microsoft-Windows-Windows Defender/Operational"
    $eventId = 5007

    try {
        $events = Get-WinEvent -LogName $logName | Where-Object { $_.Id -eq $eventId }

        $exclusionEvents = $events | Where-Object { $_.Message -match "Exclusions" }

        $patternPaths = "HKLM\\SOFTWARE\\Microsoft\\Windows Defender\\Exclusions\\Paths\\[^\s]+"
        $patternExtensions = "HKLM\\SOFTWARE\\Microsoft\\Windows Defender\\Exclusions\\Extensions\\[^\s]+"
        $patternProcesses = "HKLM\\SOFTWARE\\Microsoft\\Windows Defender\\Exclusions\\Processes\\[^\s]+"

        $exclusionEvents | ForEach-Object {
            $message = $_.Message
            if ($message -match $patternPaths) {
                [PSCustomObject]@{
                    TimeCreated = $_.TimeCreated
                    ExclusionType = 'Path'
                    ExclusionDetail = $matches[0]
                }
            }
            if ($message -match $patternExtensions) {
                [PSCustomObject]@{
                    TimeCreated = $_.TimeCreated
                    ExclusionType = 'Extension'
                    ExclusionDetail = $matches[0]
                }
            }
            if ($message -match $patternProcesses) {
                [PSCustomObject]@{
                    TimeCreated = $_.TimeCreated
                    ExclusionType = 'Process'
                    ExclusionDetail = $matches[0]
                }
            }
        }
        
    } catch {
        Write-Error "Failed to query event log: $_"
    }
}

function Test-UserPermissions {
    param (
        [Parameter(Mandatory)]
        [PSCustomObject]$Exclusions
    )

    $results = @()

    foreach ($exclusion in $Exclusions) {
        if ($exclusion.ExclusionType -eq 'Path') {
            $path = $exclusion.ExclusionDetail -replace 'HKLM\\SOFTWARE\\Microsoft\\Windows Defender\\Exclusions\\Paths\\', ''
            
            try {
                $item = Get-Item -Path $path -ErrorAction Stop
  
                $acl = Get-Acl -Path $item
                $user = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
                
                $hasPermission = $false

                foreach ($access in $acl.Access) {
                    if ($access.IdentityReference -eq $user -and $access.FileSystemRights -match "Modify|FullControl") {
                        $hasPermission = $true
                        break
                    }
                    if ($access.IdentityReference -eq "Everyone" -and $access.FileSystemRights -match "Modify|FullControl") {
                        $hasPermission = $true
                        break
                    }
                }

                $result = [PSCustomObject]@{
                    FileName = $item
                    HasPermission = $hasPermission
                }
                
                $results += $result

            } catch {
                $result = [PSCustomObject]@{
                    FileName = $item
                    HasPermission = $false
                    Error = $_.Exception.Message
                }
                $results += $result

            }
        }
    }
    return $results
}

$Exclusions = DefenderEventsExclusions
Test-UserPermissions($Exclusions)
