Sysmon for Linux: MITRE ATT&CK Validation Guide

This document describes how each security control in the config.xml file was tested using the Atomic Red Team framework.
1. Persistence - Scheduled Task/Job: Cron (T1053.003)

    Sysmon Rule Group: Cron_Persistence_Monitoring & Cron_Execution_Anomalies

    Detection Logic: Monitors file creation in /etc/cron* and suspicious command lines (base64, curl, nc) executed by the cron parent process.

    Atomic Test: Invoke-AtomicTest T1053.003 -TestNumbers 1

    What happens: The test replaces the current user's crontab with a file containing a persistent payload.

    Validation: Look for FileCreate events in /var/spool/cron/crontabs/ and ProcessCreate events with the RuleName: Cron_Persistence_Monitoring.

2. Privilege Escalation - Sudo and Sudo Caching (T1548.003)

    Sysmon Rule Group: Sudo_Privilege_Abuse

    Detection Logic: Monitors for shells (bash, sh) spawned directly by sudo and unauthorized modifications to /etc/sudoers.

    Atomic Test: Invoke-AtomicTest T1548.003 -TestNumbers 1

    What happens: The test executes sudo visudo or attempts to use sudo to gain an interactive shell.

    Validation: Look for ProcessCreate where ParentImage is /usr/bin/sudo and Image is a shell.

3. Privilege Escalation - Setuid and Setgid (T1548.001)

    Sysmon Rule Group: Privilege_Escalation_Setuid_Setgid

    Detection Logic: Detects the use of chmod to add the SUID/SGID bits (+s or 4755) and the execution of root-owned binaries from /tmp.

    Atomic Test: Invoke-AtomicTest T1548.001 -TestNumbers 1

    What happens: Copies a binary (like cp) to a new location, sets the SUID bit, and executes it to escalate privileges.

    Validation: Look for CommandLine containing u+s or 4755.

4. Command and Scripting Interpreter: Unix Shell (T1059.004)

    Sysmon Rule Group: T1059.004-Unix-Shell

    Detection Logic: High-fidelity detection for shells spawned by network tools (like curl) or unusual root shell executions.

    Atomic Test: Invoke-AtomicTest T1059.004 -TestNumbers 1

    What happens: Executes a series of shell commands via sh or bash to simulate automated script execution.

    Validation: Look for ProcessCreate events mapping shells to non-standard parent processes.

5. Defense Evasion - Indicator Removal on Host (T1070)

    Sysmon Rule Group: Process_Termination_Events

    Detection Logic: Monitors for the termination of security agents (wazuh-agent, sysmon) or system logging daemons.

    Atomic Test: Invoke-AtomicTest T1070.004 -TestNumbers 2 (File Deletion) or T1562.001 (Disable/Modify Tools).

    What happens: Attempts to stop or kill the Sysmon/Wazuh service.

    Validation: Check for ProcessTerminate events where the Image is a security binary.

6. Ingress Tool Transfer (T1105)

    Sysmon Rule Group: Network_Connection_Events

    Detection Logic: Monitors network connections initiated by common downloaders like wget, curl, nc, or scp.

    Atomic Test: Invoke-AtomicTest T1105 -TestNumbers 1

    What happens: Uses curl or wget to download a remote file to the local system.

    Validation: Look for NetworkConnect events where the Image matches the downloader list.
