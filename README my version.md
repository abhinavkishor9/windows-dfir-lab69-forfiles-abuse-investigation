# windows-dfir-lab69-forfiles-abuse-investigation
## Overview

forfiles.exe is a legitimate Windows command-line utility used to locate files based on criteria such as age, filename, and location, and optionally execute a command against the matching files.

From a SOC/DFIR perspective, forfiles.exe is interesting because an attacker can abuse a legitimate Windows utility to perform actions indirectly, such as launching commands or scripts against selected files.

This makes the investigation less about whether forfiles.exe itself is malicious and more about how it was used, what command it executed, which files were targeted, and what process activity followed.

A simplified abuse chain is:

User / Script
    ↓
forfiles.exe
    ↓
File selection criteria
    ↓
Command execution
    ↓
Child process / script
    ↓
File or system activity
    ↓
Sysmon / Wazuh telemetry



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

A Windows workstation is being investigated after forfiles.exe is observed running against a local directory. Since this legitimate Windows utility can execute commands against matching files, the analyst needs to determine what activity occurred and whether the execution was expected.

The investigation focuses on:

- The files targeted by forfiles.exe.
- The command executed against those files.
- The relationship between forfiles.exe and cmd.exe.
- The resulting file activity.
- The available Sysmon and Wazuh evidence.

## Investigation Objectives

- Establish the host, user, and investigation baseline.
- Create controlled files for forfiles.exe to process.
- Examine forfiles.exe process creation and command-line parameters.
- Confirm the forfiles.exe → cmd.exe parent-child relationship.
- Analyze the command executed through the /C parameter.
- Correlate process activity with the resulting output file.
- Validate the relevant Sysmon and Wazuh telemetry.
- Build a basic timeline of the observed activity.
- Distinguish confirmed evidence from assumptions and telemetry gaps.
- Understand why trusted Windows utilities should be investigated based on execution context and behavior, not simply their presence.

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

