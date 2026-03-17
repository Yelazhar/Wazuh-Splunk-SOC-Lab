# Wazuh-Splunk-SOC-Lab
Monitoring Windows (Sysmon) and Debian VMs. I use Wazuh to parse and filter telemetry before forwarding to Splunk, keeping the daily volume under the 500MB license limit. Focuses on efficient indexing and alert tuning. Tested via Atomic Red Team to verify detection logic for process injection and credential dumping.
<img width="850" height="1100" alt="siem-pipeline drawio(1)" src="https://github.com/user-attachments/assets/200489e7-212e-40cb-aafa-4c04a03cf4d5" />
