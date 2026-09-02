# Windows DFIR Lab 69 — Forfiles Abuse Investigation

## Overview

This lab investigates the use of the legitimate Windows utility `forfiles.exe` to identify files and execute a command against matching files. Although `forfiles.exe` is a legitimate administrative utility, its command-execution capability can also be abused to perform actions through child processes such as `cmd.exe`.

The investigation uses a controlled and benign test environment to reconstruct how `forfiles.exe` was executed, how it spawned `cmd.exe`, what command was passed to the child process, and what file activity resulted from the execution.

The objective is not to classify `forfiles.exe` as malicious by default, but to determine whether its execution context, command line, parent-child relationship, and resulting activity are consistent with legitimate administration or potential abuse.

## Lab Environment

- Operating System: Windows 11 Pro
- Hostname: `DESKTOP-9MMM37V`
- User: `DESKTOP-9MMM37V\Dell`
- PowerShell: `7.6.5`
- Sysmon: Enabled
- Wazuh Agent: Enabled
- Primary Telemetry: Sysmon Event ID 1
- SIEM Validation: Wazuh
- Investigation Directory: `C:\ForfilesAbuseLab`

## Investigation Scenario

A Windows workstation is being examined after the legitimate Windows utility `forfiles.exe` executes commands against files in a controlled directory.

The analyst needs to determine:

- What process executed `forfiles.exe`.
- What command line was supplied to `forfiles.exe`.
- Whether `forfiles.exe` created a child process.
- What command the child process executed.
- Which files were targeted by the operation.
- Whether the child process performed observable file activity.
- Whether the activity was visible through Sysmon and Wazuh.
- Whether the observed behavior represents legitimate utility use or a potentially suspicious execution pattern.

## Investigation Objectives

1. Understand the legitimate purpose and execution model of `forfiles.exe`.
2. Establish a clean baseline for the investigation host and user.
3. Create controlled files that can safely be targeted by `forfiles.exe`.
4. Capture `forfiles.exe` process creation telemetry using Sysmon Event ID 1.
5. Identify and validate the `forfiles.exe` to `cmd.exe` parent-child relationship.
6. Examine command-line arguments and execution context.
7. Correlate process execution with the resulting output file.
8. Validate whether the same telemetry is available through Wazuh.
9. Build a timeline from host setup through command execution and evidence collection.
10. Distinguish confirmed observations from telemetry limitations and assumptions.

## Investigation Workflow

```text
Environment Baseline
        |
        v
Create Controlled Test Files
        |
        v
Execute forfiles.exe
        |
        v
forfiles.exe
        |
        v
cmd.exe
        |
        v
Echo Command
        |
        v
forfiles-execution.txt
        |
        v
Sysmon / Wazuh Telemetry
        |
        v
Process + File Correlation
        |
        v
Analyst Assessment
```

## Key Evidence

### Controlled Files

Three benign text files were created:

```text
C:\ForfilesAbuseLab\Files\test01.txt
C:\ForfilesAbuseLab\Files\test02.txt
C:\ForfilesAbuseLab\Files\test03.txt
```

Each file was created at approximately `09:30:22` on `02 September 2026`.

### Forfiles Enumeration

The following command confirmed that `forfiles.exe` could enumerate the matching `.txt` files:

```powershell
forfiles /P "C:\ForfilesAbuseLab\Files" /M "*.txt" /C "cmd /c echo @file"
```

Observed output:

```text
"test01.txt"
"test02.txt"
"test03.txt"
```

### Controlled Command Execution

The following controlled command was then executed:

```powershell
forfiles /P "C:\ForfilesAbuseLab\Files" /M "*.txt" /C "cmd /c echo FORFILES_TEST >> C:\ForfilesAbuseLab\Output\forfiles-execution.txt"
```

The resulting file contained three lines:

```text
FORFILES_TEST
FORFILES_TEST
FORFILES_TEST
```

This confirms that the command was executed once for each matching file.

## Confirmed Process Chain

Sysmon Event ID 1 provided evidence of the following execution relationship:

```text
forfiles.exe
    |
    +-- cmd.exe
```

The observed child process was:

```text
C:\Windows\System32\cmd.exe
```

The parent process was:

```text
C:\Windows\System32\forfiles.exe
```

The child command line was:

```text
/c echo FORFILES_TEST >> C:\ForfilesAbuseLab\Output\forfiles-execution.txt
```

The Wazuh telemetry also exposed the parent command line:

```text
"C:\Windows\System32\forfiles.exe" /P C:\ForfilesAbuseLab\Files /M *.txt /C "cmd /c echo FORFILES_TEST >> C:\ForfilesAbuseLab\Output\forfiles-execution.txt"
```

## Important Evidence Interpretation

The presence of `forfiles.exe` alone is not sufficient to classify the activity as malicious. It is a legitimate Microsoft-signed Windows utility and can be used for normal file administration.

The stronger investigative signal comes from the complete execution context:

- `forfiles.exe` was executed with a file-selection pattern.
- The `/C` parameter supplied a command for execution.
- `forfiles.exe` spawned `cmd.exe`.
- `cmd.exe` executed a command that redirected output to a file.
- The output file contained three entries corresponding to the three matching files.
- Sysmon recorded the process creation activity.
- Wazuh exposed relevant process metadata, including the parent process and parent command line.

In a real incident, the same execution pattern would require additional context such as the initiating user, parent process, target paths, command content, timing, persistence indicators, network activity, and surrounding process activity before determining malicious intent.

## Telemetry

### Sysmon

The primary telemetry used in this investigation was:

**Event ID 1 — Process Create**

Important fields included:

- Image
- CommandLine
- ParentImage
- ParentCommandLine
- ParentProcessId
- ParentProcessGuid
- User
- IntegrityLevel
- CurrentDirectory
- LogonId
- LogonGuid
- Hashes

### Wazuh

Wazuh was used to validate SIEM visibility of the process execution.

Relevant fields observed included:

```text
data.win.eventdata.image
data.win.eventdata.parentImage
data.win.eventdata.parentCommandLine
data.win.eventdata.parentProcessId
data.win.eventdata.parentProcessGuid
data.win.eventdata.commandLine
data.win.eventdata.currentDirectory
data.win.eventdata.user
data.win.eventdata.integrityLevel
data.win.eventdata.hashes
```

## Evidence Collection

Evidence was stored under:

```text
C:\ForfilesAbuseLab\Evidence
```

Collected artifacts included:

```text
environment-baseline.txt
test-files.txt
output-file-metadata.txt
execution-output.txt
```

These artifacts preserve the environment information, test-file metadata, resulting file metadata, and command output.

## Investigation Outcome

The controlled investigation successfully demonstrated a legitimate Windows `forfiles.exe` execution followed by `cmd.exe` child-process creation.

The most significant confirmed observation is the process relationship:

```text
forfiles.exe -> cmd.exe
```

The child process executed a command that appended `FORFILES_TEST` to a controlled output file. The resulting file contained three entries, matching the three `.txt` files targeted by `forfiles.exe`.

The evidence therefore confirms the expected execution behavior of `forfiles.exe` when its `/C` option is used. It does not, by itself, establish malicious intent.

## SOC Detection Takeaway

A detection for `forfiles.exe` should not rely solely on the process name.

Useful investigative signals include:

- Unusual parent process
- Suspicious `forfiles.exe` command line
- Use of `/C` with command interpreters
- `cmd.exe` or PowerShell child processes
- Suspicious commands executed through `/C`
- Unusual target directories
- File creation or modification following execution
- Execution under an unexpected user or integrity level
- Correlation with persistence, credential access, or lateral movement activity

The broader lesson is to investigate the **execution chain and resulting behavior**, rather than treating a legitimate Windows binary as malicious simply because it appears in telemetry.


## Final Assessment

**Classification: Controlled / Benign Test Execution**

The laboratory evidence confirms `forfiles.exe` execution, child-process creation through `cmd.exe`, command-line execution, and resulting file activity. The behavior demonstrates how a legitimate Windows utility can provide an execution mechanism that deserves investigation in a real SOC environment.

No malicious payload, persistence mechanism, credential theft, or network activity was demonstrated in this controlled scenario.
