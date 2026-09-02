# Timeline 

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

