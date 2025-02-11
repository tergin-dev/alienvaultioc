# OTX Full Integration for Wazuh

This script integrates **AlienVault OTX (Open Threat Exchange)** with **Wazuh**, fetching the latest threat intelligence data (IOCs) and updating Wazuh's threat lists. The script extracts **malicious domains, IP addresses (IPv4 only), and file hashes** and appends them to Wazuh’s IOC lists for security monitoring.

## Features
✅ Fetches the latest **OTX threat intelligence** (Indicators of Compromise).  
✅ Extracts and updates **malicious domains, IPv4 addresses, and file hashes**.  
✅ **Excludes all IPv6 addresses** from processing.  
✅ **Appends** new IOCs without duplicating existing entries.  
✅ Saves and maintains a **timestamp** to fetch only new updates.  
✅ Logs operations for debugging and monitoring.

## Installation & Setup

### 1️⃣ Clone the Repository
```bash
git clone https://github.com/tergin-dev/alienvaultioc.git
cd alienvaultioc/
```

### 2️⃣ Install Dependencies
Ensure Python and `requests` are installed:
```bash
pip install requests
```

### 3️⃣ Configure API Key
Edit **`otx_full_integration.py`** and replace the `OTX_API_KEY` variable with your **AlienVault OTX API key**:
```python
OTX_API_KEY = "YOUR_OTX_API_KEY_HERE"
```

### 4️⃣ Run the Script Manually
```bash
python otx_full_integration.py
```

This will fetch the latest OTX pulses, extract **malicious domains, IPv4 addresses, and file hashes**, and update the IOC lists.

## Automating Execution (Optional)
To automate periodic execution, add a **cron job**:

```bash
crontab -e
```
Add the following line to fetch updates every **6 hours**:
```
0 */6 * * * /usr/bin/python3 /path/to/otx_full_integration.py
```

## File Structure

| File | Description |
|------|------------|
| `otx_full_integration.py` | Main Python script for fetching and updating IOCs |
| `otx-ioc.json` | Stores raw threat intelligence data from OTX |
| `otx-domains` | List of malicious domains for Wazuh |
| `otx-ips` | List of **malicious IPv4 addresses** (No IPv6) |
| `otx-hashes` | List of malicious file hashes |
| `last_fetch.json` | Stores the last fetch timestamp to avoid duplicate requests |
| `otx_integration.log` | Log file for debugging and monitoring |

## Wazuh Configuration
Ensure Wazuh is set up to **monitor these IOC lists** by adding them to your Wazuh **ruleset**. You can configure Wazuh to alert when a match occurs with any of the fetched **malicious domains, IPs, or hashes**.

---

## Troubleshooting

### 🔹 Permission Issues?
Run the script as root or use `sudo`:
```bash
sudo python otx_full_integration.py
```

### 🔹 No Data Fetching?
- Ensure your **OTX API key** is valid.
- Check if the **OTX service is reachable**:
  ```bash
  curl -H "X-OTX-API-KEY: YOUR_OTX_API_KEY_HERE" https://otx.alienvault.com/api/v1/pulses/subscribed
  ```
- Review the log file for errors:
  ```bash
  cat /var/log/otx_integration.log
  ```

---

<img width="1202" alt="image" src="https://github.com/user-attachments/assets/a8be24e3-cd12-4492-8890-47362e6a21b4" />



## 📌 Notes
- This script **only includes IPv4** addresses (IPv6 is discarded).  
- The fetched data is **incremental**, meaning only new IOCs are retrieved after the last fetch.  
- The script is designed to **run periodically** for continuous threat updates.  

---

## 🛠️ Future Enhancements
- [ ] Add **Wazuh rule automation** for detected IOCs.  
- [ ] Enhance logging for better debugging.  
- [ ] Add **Docker support** for easier deployment.  

---

## 📜 License
This project is open-source and free to use under the **MIT License**.
