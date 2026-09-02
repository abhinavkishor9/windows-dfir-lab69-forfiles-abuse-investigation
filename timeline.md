# Timeline — Lab 69 Forfiles Abuse Investigation

## Investigation Timeline

| Time | Event | Evidence | Significance |
|---|---|---|---|
| 09:28:54 | Environment baseline collected | PowerShell console | Establishes host, user, and investigation start time |
| 09:28 | `C:\ForfilesAbuseLab` created | PowerShell output | Establishes controlled investigation workspace |
| 09:28:59 | Baseline evidence saved | `environment-baseline.txt` | Preserves host and PowerShell information |
| 09:30:22 | Three test files created | PowerShell metadata | Establishes controlled target files |
| 09:30:22 | `test01.txt`, `test02.txt`, `test03.txt` created | `test-files.txt` | Provides file-selection targets |
| 09:31:24 | `forfiles.exe` executed | Sysmon Event ID 1 | Confirms process creation |
| 09:31:24 | `forfiles.exe` used with `/P`, `/M`, and `/C` | Sysmon Event ID 1 | Shows file selection and command execution parameters |
| 09:34:46 | `cmd.exe` created | Sysmon Event ID 1 / Wazuh | Confirms child process execution |
| 09:34:46 | `cmd.exe` executed output redirection command | Sysmon Event ID 1 | Connects process execution to file activity |
| 09:34:46 | `forfiles-execution.txt` created | Filesystem metadata | Confirms resulting artifact |
| 09:34:46 | Output file recorded as 48 bytes | `output-file-metadata.txt` | Provides artifact metadata |
| 09:41 | Evidence files collected | Evidence directory | Preserves investigation results |
| 09:41 | Output content preserved | `execution-output.txt` | Confirms three command executions |

## Process Timeline

```text
09:31:24
    |
    +-- forfiles.exe
        |
        | /P C:\ForfilesAbuseLab\Files
        | /M *.txt
        | /C "cmd /c echo @file"
        |
        +-- File enumeration
```

The controlled command-execution stage later produced:

```text
09:34:46
    |
    +-- forfiles.exe
        |
        +-- cmd.exe
            |
            +-- /c echo FORFILES_TEST >>
                C:\ForfilesAbuseLab\Output\forfiles-execution.txt
                    |
                    +-- FORFILES_TEST
                    +-- FORFILES_TEST
                    +-- FORFILES_TEST
```

## Evidence Correlation

### Host

```text
DESKTOP-9MMM37V
```

### User

```text
DESKTOP-9MMM37V\Dell
```

### Parent Process

```text
C:\Windows\System32\forfiles.exe
```

### Child Process

```text
C:\Windows\System32\cmd.exe
```

### Parent Command

```text
"C:\Windows\System32\forfiles.exe" /P C:\ForfilesAbuseLab\Files /M *.txt /C "cmd /c echo FORFILES_TEST >> C:\ForfilesAbuseLab\Output\forfiles-execution.txt"
```

### Child Command

```text
/c echo FORFILES_TEST >> C:\ForfilesAbuseLab\Output\forfiles-execution.txt
```

### Target Directory

```text
C:\ForfilesAbuseLab\Files
```

### Output Artifact

```text
C:\ForfilesAbuseLab\Output\forfiles-execution.txt
```

## Process Relationship

The strongest process correlation obtained during the investigation was:

```text
forfiles.exe
    |
    +-- cmd.exe
```

The `cmd.exe` event contained:

```text
ParentImage:
C:\Windows\System32\forfiles.exe
```

This confirms the parent-child relationship through endpoint telemetry.

## Timeline Assessment

The timeline demonstrates a controlled progression from environment preparation to file creation, `forfiles.exe` execution, child-process creation, output-file creation, and evidence preservation.

The timestamps and artifacts provide a coherent sequence:

```text
Baseline
   ↓
Create target files
   ↓
Execute forfiles.exe
   ↓
Create cmd.exe child process
   ↓
Execute command
   ↓
Create/modify output file
   ↓
Collect evidence
```

## Final Timeline Conclusion

The available evidence supports a consistent execution chain in which `forfiles.exe` processed three controlled `.txt` files and invoked `cmd.exe` to execute the supplied command. The child process created the expected output artifact, which contained three entries corresponding to the three matching files.

The activity was intentionally benign and controlled. In a real SOC investigation, the same timeline structure could be used to determine whether the command executed through `forfiles.exe` represented routine administration or a suspicious execution technique.
