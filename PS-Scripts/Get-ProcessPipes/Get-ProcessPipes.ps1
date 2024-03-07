function Get-ProcessPipes{
    param(
        [Parameter(Mandatory=$false)]
        [string]$CSV,
        [Parameter(Mandatory=$false)]
        [switch]$All
    )

    Add-Type -TypeDefinition  @"
        using System;
        using System.Diagnostics;
        using System.Runtime.InteropServices;
     
        public static class Kernel32
        {
            [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
            public static extern IntPtr CreateFile(
                  string filename,
                  System.IO.FileAccess access,
                  System.IO.FileShare share,
                  IntPtr securityAttributes,
                  System.IO.FileMode creationDisposition,
                  uint flagsAndAttributes,
                  IntPtr templateFile);

            [DllImport("kernel32.dll", SetLastError = true)]
            public static extern bool GetNamedPipeServerProcessId(IntPtr hPipe, out int ClientProcessId);
        
            [DllImport("kernel32.dll", SetLastError=true)]
            public static extern bool CloseHandle(IntPtr hObject);
        }
"@

    #Get list of pipes
    $pipes = Get-ChildItem -Path \\.\pipe\ | select -ExpandProperty FullName
    $output = @()
    $unknownPipes = @()
    $pipeOwner = 0

    foreach($pipe in $pipes)
    {
        #Open a handle to the named pipe
        $hPipe = [Kernel32]::CreateFile($pipe, [System.IO.FileAccess]::Read, [System.IO.FileShare]::None, [System.IntPtr]::Zero, [System.IO.FileMode]::Open, [System.UInt32]::0x80,[System.IntPtr]::Zero)
        
        # If CreateFile returned INVALID_HANDLE_VALUE, we won't be able to get any additional information for this pipe,
        # so go to the next named pipe.
        if ($hPipe -eq -1) 
        {
            #add it to an array of pipes to deal with later
            $unknownPipes += $pipe
            continue
        }

        #Get the owning pid of the pipe
        $pipeOwnerFound = [Kernel32]::GetNamedPipeServerProcessId([System.IntPtr]$hPipe, [ref]$pipeOwner)
        if ($pipeOwnerFound)
        {
            # Now that we have the process id, Get process name
            $processName = Get-WmiObject -Query "SELECT Caption FROM Win32_Process WHERE ProcessID = $pipeOwner" | select -ExpandProperty Caption
            
            # Add to the output results
            $output += New-Object PSObject -Property @{
                ProcessID = $pipeOwner
                ProcessName = $processName
                NamedPipe = $pipe
            }

        }
        
        #close the handle to the pipe
        $closeHandle = [Kernel32]::CloseHandle($hPipe)
        if(!$closeHandle)
        {
            Write-Host "[!] CloseHandle: Error closing pipe handle."
        }
    }

    #If "-All" was specified, add the unresolved pipes to the output.
    if ($All)
    {

        foreach ($unk in $unknownPipes)
        {
            $output += New-Object PSObject -Property @{
                    ProcessID = "-"
                    ProcessName = "-"
                    NamedPipe = $unk
                }
        }

    }

    #Export to csv if "-CSV" was specified. Otherwise, write to console.
    if ($csv)
    {
        $output | Export-Csv $CSV -NoTypeInformation
    }
    else
    {
        $output
    }
}