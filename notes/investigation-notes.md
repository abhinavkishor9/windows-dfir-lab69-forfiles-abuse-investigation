# Investigation Notes — Lab 69 Forfiles Abuse Investigation

## 1. Investigation Purpose

The purpose of this investigation was to examine how `forfiles.exe` behaves when used to identify matching files and execute a command against them.

The investigation was intentionally performed using benign commands and controlled files. The focus was on reconstructing the execution chain and understanding what evidence is available to a SOC analyst.

## 2. Environment Baseline

The laboratory environment was established on:

```text
Hostname: DESKTOP-9MMM37V
User: desktop-9mmm37v\dell
PowerShell: 7.6.5
Initial Time: 02 September 2026 09:28:54
```

The investigation workspace was created at:

```text
C:\ForfilesAbuseLab
```

The following subdirectories were created:

```text
C:\ForfilesAbuseLab\Files
C:\ForfilesAbuseLab\Output
C:\ForfilesAbuseLab\Evidence
```

The baseline was preserved in:

```text
C:\ForfilesAbuseLab\Evidence\environment-baseline.txt
```

## 3. Controlled Test Files

Three benign text files were created:

```text
test01.txt
test02.txt
test03.txt
```

Location:

```text
C:\ForfilesAbuseLab\Files
```

Observed metadata showed all three files were created at approximately:

```text
02 September 2026 09:30:22
```

Each file was 18 bytes.

The files contained simple laboratory test strings and were not malicious.

## 4. Legitimate Forfiles Enumeration

The first `forfiles.exe` test was designed only to identify matching files:

```powershell
forfiles /P "C:\ForfilesAbuseLab\Files" /M "*.txt" /C "cmd /c echo @file"
```

Observed output:

```text
"test01.txt"
"test02.txt"
"test03.txt"
```

This established that the `/P` path and `/M` file pattern correctly identified the three test files.

## 5. Sysmon Process Evidence

Sysmon Event ID 1 was reviewed for the `forfiles.exe` execution.

Observed values included:

```text
OriginalFileName: forfiles.exe
CommandLine: "C:\Windows\System32\forfiles.exe" /P C:\ForfilesAbuseLab\Files /M *.txt /C "cmd /c echo @file"
CurrentDirectory: C:\Windows\System32\
User: DESKTOP-9MMM37V\Dell
IntegrityLevel: High
```

The event was logged at:

```text
02 September 2026 09:31:24
```

The binary was identified as:

```text
C:\Windows\System32\forfiles.exe
```

The available metadata identified Microsoft Corporation as the company.

## 6. Controlled Command Execution

A second execution was performed to demonstrate command execution against each matching file:

```powershell
forfiles /P "C:\ForfilesAbuseLab\Files" /M "*.txt" /C "cmd /c echo FORFILES_TEST >> C:\ForfilesAbuseLab\Output\forfiles-execution.txt"
```

No direct console output was produced by the command.

The resulting output file was:

```text
C:\ForfilesAbuseLab\Output\forfiles-execution.txt
```

## 7. Output Verification

The output file contained:

```text
FORFILES_TEST
FORFILES_TEST
FORFILES_TEST
```

The three lines correspond to the three matching `.txt` files.

File metadata:

```text
FullName:
C:\ForfilesAbuseLab\Output\forfiles-execution.txt

Length:
48 bytes

CreationTime:
02 September 2026 09:34:46

LastWriteTime:
02 September 2026 09:34:46
```

This provides a direct correlation between the controlled `forfiles.exe` execution and the resulting file artifact.

## 8. Child Process Investigation

Sysmon Event ID 1 was reviewed for the `cmd.exe` process created during the controlled execution.

Observed values included:

```text
Image:
C:\Windows\System32\cmd.exe

OriginalFileName:
Cmd.Exe

CommandLine:
/c echo FORFILES_TEST >> C:\ForfilesAbuseLab\Output\forfiles-execution.txt

CurrentDirectory:
C:\ForfilesAbuseLab\Files\

User:
DESKTOP-9MMM37V\Dell

IntegrityLevel:
High
```

The event was logged at:

```text
02 September 2026 09:34:46
```

Most importantly, the Wazuh event identified:

```text
ParentImage:
C:\Windows\System32\forfiles.exe
```

and:

```text
ParentProcessId:
23204
```

This confirms the expected relationship:

```text
forfiles.exe
    |
    +-- cmd.exe
```

## 9. Parent Command Line

The Wazuh telemetry exposed the complete parent command line:

```text
"C:\Windows\System32\forfiles.exe" /P C:\ForfilesAbuseLab\Files /M *.txt /C "cmd /c echo FORFILES_TEST >> C:\ForfilesAbuseLab\Output\forfiles-execution.txt"
```

This is particularly useful because it shows both the file-selection logic and the command supplied to the `/C` parameter.

The command can be interpreted as:

```text
/P
Target directory

/M
File matching pattern

/C
Command to execute for each matching file
```

The command executed through `/C` was:

```text
cmd /c echo FORFILES_TEST >> C:\ForfilesAbuseLab\Output\forfiles-execution.txt
```

## 10. Execution Context

The `forfiles.exe` and `cmd.exe` activity was associated with:

```text
User:
DESKTOP-9MMM37V\Dell
```

The integrity level was:

```text
High
```

The events also shared the same:

```text
LogonGuid
LogonId
TerminalSessionId
```

This provides useful correlation context when reconstructing process activity.

## 11. File Correlation

The investigation was able to connect:

```text
forfiles.exe
    |
    v
cmd.exe
    |
    v
echo FORFILES_TEST
    |
    v
forfiles-execution.txt
```

The output file contained three lines because the command was applied to three matching files.

This demonstrates why process telemetry should be correlated with filesystem artifacts whenever possible.

## 12. Wazuh Investigation

Wazuh was searched for process execution information associated with:

```text
forfiles.exe
cmd.exe
```

The Wazuh telemetry exposed important Sysmon-derived process fields, including:

```text
image
parentImage
parentCommandLine
parentProcessId
parentProcessGuid
commandLine
currentDirectory
user
integrityLevel
hashes
```

The presence of the parent process information was especially valuable because it allowed the child `cmd.exe` execution to be linked back to `forfiles.exe`.

## 13. Evidence Collected

The following evidence files were created:

### environment-baseline.txt

Contains:

- Hostname
- User
- Initial investigation time
- PowerShell version

### test-files.txt

Contains metadata for the controlled `.txt` files.

### output-file-metadata.txt

Contains metadata for the resulting output file.

### execution-output.txt

Contains the contents of:

```text
forfiles-execution.txt
```

The collected evidence provides both environmental context and execution results.

## 14. Analyst Assessment

### Confirmed

- `forfiles.exe` executed from `C:\Windows\System32`.
- `forfiles.exe` was used to identify `.txt` files.
- Three controlled test files were matched.
- `forfiles.exe` was used with the `/C` command-execution option.
- `cmd.exe` was created as a child process.
- The child command appended text to the controlled output file.
- The output file contained three entries.
- Sysmon Event ID 1 captured the process creation activity.
- Wazuh exposed parent-child process information.

### Not Demonstrated

The laboratory did not demonstrate:

- Malware execution
- Persistence
- Credential theft
- Privilege escalation
- Lateral movement
- Command-and-control communication
- Destructive file activity

### Analyst Conclusion

The observed behavior is consistent with the expected functionality of `forfiles.exe` in a controlled administrative test.

However, the same execution mechanism could become suspicious if the command executed through `/C` performed actions such as downloading files, executing scripts, modifying persistence locations, deleting evidence, or interacting with sensitive system resources.

Therefore, the binary itself should not be the sole detection criterion. The command line, parent process, child process, user context, target path, and resulting activity provide the stronger investigative context.
