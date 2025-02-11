import requests
import json
import os
import time
import ipaddress

# AlienVault OTX API Key
OTX_API_KEY = "<ENTER-API-KEY>"
OTX_BASE_URL = "https://otx.alienvault.com/api/v1/pulses/subscribed"
OTX_HEADERS = {"X-OTX-API-KEY": OTX_API_KEY}

# Paths for IOC list, last fetch timestamp, and Wazuh lists
IOC_JSON_FILE = "/var/ossec/etc/lists/otx/otx-ioc.json"
LAST_FETCH_FILE = "/var/ossec/etc/lists/otx/last_fetch.json"
IOC_DOMAIN_LIST = "/var/ossec/etc/lists/otx/otx-domains"
IOC_IP_LIST = "/var/ossec/etc/lists/otx/otx-ips"
IOC_HASH_LIST = "/var/ossec/etc/lists/otx/otx-hashes"
LOG_FILE = "/var/log/otx_integration.log"

# Retry settings
RETRY_COUNT = 3
RETRY_DELAY = 10

# Ensure directories exist
os.makedirs(os.path.dirname(IOC_JSON_FILE), exist_ok=True)
os.makedirs(os.path.dirname(IOC_DOMAIN_LIST), exist_ok=True)
os.makedirs(os.path.dirname(IOC_IP_LIST), exist_ok=True)
os.makedirs(os.path.dirname(IOC_HASH_LIST), exist_ok=True)

# Function to log messages to a file
def log_message(message):
    with open(LOG_FILE, "a") as log_file:
        log_file.write(f"{time.strftime('%Y-%m-%d %H:%M:%S')} - {message}\n")
    print(message)

# Function to get the last fetch timestamp
def get_last_fetch_timestamp():
    if os.path.exists(LAST_FETCH_FILE):
        with open(LAST_FETCH_FILE, 'r') as f:
            data = json.load(f)
            return data.get("last_fetch", "1970-01-01T00:00:00.000000")
    return "1970-01-01T00:00:00.000000"

# Function to save the last fetch timestamp
def save_last_fetch_timestamp(latest_modified):
    with open(LAST_FETCH_FILE, 'w') as f:
        json.dump({"last_fetch": latest_modified}, f, indent=2)
    log_message(f"Saved last fetch timestamp: {latest_modified}")

# Function to load existing IOCs from files
def load_existing_iocs(file_path):
    if os.path.exists(file_path):
        with open(file_path, 'r') as f:
            return set(line.split(':')[0].strip().strip('"') for line in f)
    return set()

# Function to check if an IP is IPv4
def is_ipv4(ip):
    try:
        ip_obj = ipaddress.ip_address(ip)
        return ip_obj.version == 4  # Only allow IPv4
    except ValueError:
        return False  # Invalid IPs are discarded

# Function to extract and write IOCs in the correct format
def extract_iocs():
    try:
        with open(IOC_JSON_FILE, 'r') as f:
            iocs = json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        log_message("File missing or invalid: skipping extraction.")
        return

    existing_domains = load_existing_iocs(IOC_DOMAIN_LIST)
    existing_ips = load_existing_iocs(IOC_IP_LIST)
    existing_hashes = load_existing_iocs(IOC_HASH_LIST)

    new_domains, new_ips, new_hashes = set(), set(), set()
    domain_counter = len(existing_domains) + 1
    ip_counter = len(existing_ips) + 1
    hash_counter = len(existing_hashes) + 1

    for pulse in iocs:
        for indicator in pulse.get('indicators', []):
            ioc_type = indicator.get('type')
            ioc_value = indicator.get('indicator')

            if not ioc_value:
                continue

            if ioc_type == 'domain':
                if ioc_value not in existing_domains and ioc_value not in new_domains:
                    new_domains.add(f"{ioc_value}:malicious-domain-{domain_counter}")
                    domain_counter += 1

            elif ioc_type == 'IPv4' and is_ipv4(ioc_value):  # Ensure only IPv4
                if ioc_value not in existing_ips and ioc_value not in new_ips:
                    new_ips.add(f"{ioc_value}:malicious-ip-{ip_counter}")
                    ip_counter += 1

            elif ioc_type.startswith('FileHash'):
                if ioc_value not in existing_hashes and ioc_value not in new_hashes:
                    new_hashes.add(f"{ioc_value}:malicious-hash-{hash_counter}")
                    hash_counter += 1

    if new_domains:
        with open(IOC_DOMAIN_LIST, 'a') as domain_file:
            domain_file.write('\n'.join(new_domains) + '\n')
        log_message(f"Added {len(new_domains)} new domains.")

    if new_ips:
        with open(IOC_IP_LIST, 'a') as ip_file:
            ip_file.write('\n'.join(new_ips) + '\n')
        log_message(f"Added {len(new_ips)} new IPv4 addresses.")

    if new_hashes:
        with open(IOC_HASH_LIST, 'a') as hash_file:
            hash_file.write('\n'.join(new_hashes) + '\n')
        log_message(f"Added {len(new_hashes)} new file hashes.")

# Function to fetch OTX pulses and dynamically update Wazuh IOC lists
def fetch_new_pulses():
    page = 1
    last_fetch = get_last_fetch_timestamp()
    log_message(f"Fetching pulses modified after {last_fetch}...")

    all_pulses = []

    try:
        with open(IOC_JSON_FILE, 'r') as ioc_file:
            existing_data = json.load(ioc_file)
    except (FileNotFoundError, json.JSONDecodeError):
        existing_data = []

    while True:
        url = f"{OTX_BASE_URL}?page={page}&modified_since={last_fetch}"
        log_message(f"Processing page {page}...")

        for attempt in range(RETRY_COUNT):
            try:
                response = requests.get(url, headers=OTX_HEADERS)
                if response.status_code == 200:
                    otx_data = response.json()
                    results = otx_data.get('results', [])

                    if not results:
                        log_message("No more data to process.")
                        return

                    all_pulses.extend(results)
                    with open(IOC_JSON_FILE, 'w') as ioc_file:
                        json.dump(existing_data + all_pulses, ioc_file, indent=2)

                    extract_iocs()
                    page += 1
                    break
                elif response.status_code == 504:
                    log_message(f"504 Gateway Timeout. Retrying in {RETRY_DELAY} seconds...")
                    time.sleep(RETRY_DELAY)
                else:
                    log_message(f"Error fetching data: {response.status_code}")
                    break
            except Exception as e:
                log_message(f"Error on attempt {attempt + 1}: {e}")
                time.sleep(RETRY_DELAY)

    if all_pulses:
        save_last_fetch_timestamp(all_pulses[0].get("modified"))

# Main function
def main():
    fetch_new_pulses()

if __name__ == "__main__":
    main()