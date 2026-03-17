## 🛠 Pipeline Architecture
<img width="850" height="1100" alt="siem-pipeline drawio(1)" src="https://github.com/user-attachments/assets/29175166-83e1-4bd3-9c3d-23f7a8c0bb2e" />

### 1. Data Collection & Normalization
* **Endpoints:** Sysmon (Windows) and SysmonForLinux (Debian) capture kernel-level telemetry.
* **Wazuh Manager:** Processes raw events through a specialized **Decoding Layer** to produce structured JSON.

### 2. Filtering & Enrichment
* **Wazuh Rules:** Events are filtered by severity (Alert Level 3+). High-noise events (Level 1-2) are dropped to preserve Splunk license volume.
* **MITRE Mapping:** Applied `200150-sysmon_for_linux_rules.xml` to align Linux telemetry with the MITRE ATT&CK framework.

### 3. Analytics & Visualization
* **Splunk Ingestion:** Alerts are picked up locally via `inputs.conf`.
* **Field Extraction:** Automated parsing via `props.conf` ensures all Sysmon fields are searchable as distinct key-value pairs.

