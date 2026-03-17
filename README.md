# Wazuh-Splunk-SOC-Lab
Monitoring Windows (Sysmon) and Debian VMs. I use Wazuh to parse and filter telemetry before forwarding to Splunk, keeping the daily volume under the 500MB license limit. Focuses on efficient indexing and alert tuning. Tested via Atomic Red Team to verify detection logic for process injection and credential dumping.
