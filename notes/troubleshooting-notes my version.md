# Troubleshooting Notes 

## 1. Lab Directory Structure

The investigation required a dedicated working directory.

The following commands were used:

```powershell
New-Item -Path "C:\ForfilesAbuseLab" -ItemType Directory -Force
New-Item -Path "C:\ForfilesAbuseLab\Files" -ItemType Directory -Force
New-Item -Path "C:\ForfilesAbuseLab\Output" -ItemType Directory -Force
New-Item -Path "C:\ForfilesAbuseLab\Evidence" -ItemType Directory -Force
```

The structure was verified using:

```powershell
Get-ChildItem "C:\ForfilesAbuseLab"
```

Expected directories:

```text
Evidence
Files
Output
```

## 2. PowerShell Working Directory

The PowerShell prompt was:

```text
PS C:\Windows\System32>
```

This was not an issue because the commands used absolute paths such as:

```text
C:\ForfilesAbuseLab\Files
```

and:

```text
C:\ForfilesAbuseLab\Output
```

Using absolute paths reduced ambiguity during evidence collection.

## 3. Creating the Test Files

The controlled files were created with:

```powershell
"Lab test file 01" | Set-Content "C:\ForfilesAbuseLab\Files\test01.txt"
"Lab test file 02" | Set-Content "C:\ForfilesAbuseLab\Files\test02.txt"
"Lab test file 03" | Set-Content "C:\ForfilesAbuseLab\Files\test03.txt"
```

Their existence and metadata were verified with:

```powershell
Get-ChildItem "C:\ForfilesAbuseLab\Files" |
Select-Object Name, Length, CreationTime, LastWriteTime
```

The expected result was three files:

```text
test01.txt
test02.txt
test03.txt
```

## 4. Verifying Forfiles Before Command Execution

Before testing file modification, a simple enumeration command was used:

```powershell
forfiles /P "C:\ForfilesAbuseLab\Files" /M "*.txt" /C "cmd /c echo @file"
```

This returned:

```text
"test01.txt"
"test02.txt"
"test03.txt"
```

This was useful because it confirmed that the file-selection criteria were working before introducing the output operation.

## 5. Output File Creation

The controlled execution command was:

```powershell
forfiles /P "C:\ForfilesAbuseLab\Files" /M "*.txt" /C "cmd /c echo FORFILES_TEST >> C:\ForfilesAbuseLab\Output\forfiles-execution.txt"
```

The command produced no console output.

The output was instead redirected to:

```text
C:\ForfilesAbuseLab\Output\forfiles-execution.txt
```

The file was verified with:

```powershell
Get-Content "C:\ForfilesAbuseLab\Output\forfiles-execution.txt"
```

The result contained three lines:

```text
FORFILES_TEST
FORFILES_TEST
FORFILES_TEST
```

## 6. Understanding the Three Output Lines

The three output lines were expected because three `.txt` files matched:

```text
test01.txt
test02.txt
test03.txt
```

The `/C` command is therefore executed for each matching file.

This behavior also provides a useful correlation point during investigation.

## 7. Sysmon Event ID 1 Investigation

Sysmon Event ID 1 was used as the primary process-creation telemetry.

The relevant Event Viewer location was:

```text
Applications and Services Logs
    -> Microsoft
        -> Windows
            -> Sysmon
                -> Operational
```

The investigation filtered for:

```text
Event ID: 1
```

The `forfiles.exe` process was observed at approximately:

```text
09:31:24
```

The later `cmd.exe` process was observed at approximately:

```text
09:34:46
```

## 8. Parent-Child Relationship

The child `cmd.exe` event contained parent-process information.

Observed:

```text
ParentImage:
C:\Windows\System32\forfiles.exe
```

This was important because it allowed the process relationship to be established from telemetry rather than assumed from the command syntax.

The confirmed relationship was:

```text
forfiles.exe
    |
    +-- cmd.exe
```

## 9. Wazuh Visibility

Wazuh provided useful process metadata for the investigation.

The observed event included fields such as:

```text
image
parentImage
parentCommandLine
parentProcessId
parentProcessGuid
currentDirectory
user
integrityLevel
hashes
```

The Wazuh event identified the parent as:

```text
C:\Windows\System32\forfiles.exe
```

and the child as:

```text
C:\Windows\System32\cmd.exe
```

This demonstrated that the relevant Sysmon process telemetry was available through the Wazuh investigation interface.

## 10. File Activity Telemetry Consideration

The output file was verified directly through PowerShell:

```powershell
Get-Item "C:\ForfilesAbuseLab\Output\forfiles-execution.txt" |
Select-Object FullName, Length, CreationTime, LastWriteTime
```

The file showed:

```text
Length: 48
CreationTime: 02-09-2026 09:34:46
LastWriteTime: 02-09-2026 09:34:46
```

The file's existence and metadata therefore provide direct filesystem evidence.

If Sysmon Event ID 11 is available, it can be checked for file creation activity. However, Event ID 11 should not be treated as a guaranteed record for every subsequent file append or modification. The filesystem metadata and process command line should be considered together.

## 11. Evidence Preservation

The investigation artifacts were written to:

```text
C:\ForfilesAbuseLab\Evidence
```

Commands used included:

```powershell
Get-ChildItem "C:\ForfilesAbuseLab\Files" -Force |
Select-Object FullName, Length, CreationTime, LastWriteTime |
Out-File "C:\ForfilesAbuseLab\Evidence\test-files.txt"
```

```powershell
Get-Item "C:\ForfilesAbuseLab\Output\forfiles-execution.txt" |
Select-Object FullName, Length, CreationTime, LastWriteTime |
Out-File "C:\ForfilesAbuseLab\Evidence\output-file-metadata.txt"
```

```powershell
Get-Content "C:\ForfilesAbuseLab\Output\forfiles-execution.txt" |
Out-File "C:\ForfilesAbuseLab\Evidence\execution-output.txt"
```

The evidence directory was then verified:

```powershell
Get-ChildItem "C:\ForfilesAbuseLab\Evidence"
```

