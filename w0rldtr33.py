import configparser
import re
import requests
import argparse
import pandas as pd
import os
from datetime import datetime

# Load API keys from w0rldtr33.ini file
config = configparser.ConfigParser()
config.read('w0rldtr33.ini')

virustotal_api_key = config.get('API_KEYS', 'VIRUSTOTAL_API_KEY')
greynoise_api_key = config.get('API_KEYS', 'GREYNOISE_API_KEY')

# Regular expressions for different types of IOCs (IP, URL, file hash)
ip_regex = r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b"  # Matches IPv4 addresses
url_regex = r"https?://[^\s/$.?#].[^\s]*"  # Matches HTTP/HTTPS URLs
hash_regex = r"\b[a-fA-F0-9]{32,64}\b"  # Matches MD5 (32 characters), SHA-1 (40), and SHA-256 (64)

# Function to classify the type of IOC (IP, URL, File Hash, or Unknown)
def classify_ioc(ioc):
    if re.match(ip_regex, ioc):
        return 'IP Address'
    elif re.match(url_regex, ioc):
        return 'URL'
    elif re.match(hash_regex, ioc):
        return 'File Hash'
    else:
        return 'Unknown'

# Function to query VirusTotal for information about an IOC
def virustotal_lookup(ioc, ioc_type):
    if ioc_type == 'ip-address':
        url = "https://www.virustotal.com/vtapi/v2/ip-address/report"
        params = {'apikey': virustotal_api_key, 'ip': ioc}
    elif ioc_type == 'url':
        url = "https://www.virustotal.com/vtapi/v2/url/report"
        params = {'apikey': virustotal_api_key, 'resource': ioc}
    elif ioc_type == 'file':
        url = "https://www.virustotal.com/vtapi/v2/file/report"
        params = {'apikey': virustotal_api_key, 'resource': ioc}
    else:
        return {'response_code': -1, 'verbose_msg': 'Unsupported IOC type'}
    
    response = requests.get(url, params=params)
    result = response.json()

    # Handle case when VirusTotal says resource is not available
    if result.get('response_code') == 0:
        print(f"VirusTotal: {result.get('verbose_msg')}")
        return None  # Return None for unscanned or unavailable resources

    return result

# Function to query GreyNoise for information about an IP address
def greynoise_lookup(ip):
    url = f"https://api.greynoise.io/v3/community/{ip}"
    headers = {'key': greynoise_api_key}
    response = requests.get(url, headers=headers)
    
    if response.status_code == 200:
        return response.json()
    else:
        print(f"Error fetching data from GreyNoise for {ip}: {response.status_code}")
        return {}

# Function to analyze a single IOC and return the result
def analyze_ioc(ioc):
    ioc_type = classify_ioc(ioc)
    
    if ioc_type == 'IP Address':
        print(f"Analyzing IP {ioc} with GreyNoise and VirusTotal...")
        greynoise_result = greynoise_lookup(ioc)
        virustotal_result = virustotal_lookup(ioc, 'ip-address')
        return {
            'IOC': ioc, 'Type': 'IP Address',
            'GreyNoise': greynoise_result,
            'VirusTotal': virustotal_result
        }
    
    elif ioc_type == 'URL':
        print(f"Analyzing URL {ioc} with VirusTotal...")
        virustotal_result = virustotal_lookup(ioc, 'url')
        return {
            'IOC': ioc, 'Type': 'URL',
            'VirusTotal': virustotal_result
        }
    
    elif ioc_type == 'File Hash':
        print(f"Analyzing file hash {ioc} with VirusTotal...")
        virustotal_result = virustotal_lookup(ioc, 'file')
        
        # Handle case where hash has not been scanned
        if virustotal_result is None:
            return {
                'IOC': ioc,
                'Type': 'File Hash',
                'VirusTotal': {'verbose_msg': 'Not found in VirusTotal database'}
            }
        
        return {
            'IOC': ioc, 'Type': 'File Hash',
            'VirusTotal': virustotal_result
        }
    
    else:
        print(f"Unknown IOC type for {ioc}")
        return {'IOC': ioc, 'Type': 'Unknown'}

# Function to print analysis results in a readable format
def print_results(result):
    if result is None:
        print("No valid data to display for this IOC.")
        return

    ioc = result['IOC']
    ioc_type = result['Type']
    print("\n" + "="*80)
    print(f"\nIOC: {ioc}")
    print(f"Type: {ioc_type}")
    
    if ioc_type == 'IP Address':
        print("\n--- GreyNoise Information ---")
        greynoise_data = result.get('GreyNoise', {})
        
        # Ensure fields are present and handle default None values
        ip = greynoise_data.get('ip', 'None')
        noise = greynoise_data.get('noise', 'None')
        riot = greynoise_data.get('riot', 'None')
        classification = greynoise_data.get('classification', 'None')
        name = greynoise_data.get('name', 'None')
        last_seen = greynoise_data.get('last_seen', 'None')
        greynoise_link = f"https://viz.greynoise.io/ip/{ioc}" if ip != 'None' else 'None'

        print(f"IP: {ip}")
        print(f"Noise: {noise}")
        print(f"RIOT: {riot}")
        print(f"Classification: {classification}")
        print(f"Name: {name}")
        print(f"GreyNoise Link: {greynoise_link}")
        print(f"Last Seen: {last_seen}")
        
        print("\n--- VirusTotal Information ---")
        vt_data = result['VirusTotal']
        print(f"Response Code: {vt_data.get('response_code', 'None')}")
        print(f"Verbose Message: {vt_data.get('verbose_msg', 'None')}")
        
        if 'detected_urls' in vt_data:
            print(f"Detected URLs: {len(vt_data['detected_urls'])}")
            for url_info in vt_data['detected_urls'][:3]:
                print(f"URL: {url_info['url']}, Positives: {url_info['positives']}/{url_info['total']}")
        
        if 'detected_downloaded_samples' in vt_data:
            print(f"Detected Downloaded Samples: {len(vt_data['detected_downloaded_samples'])}")
            for sample in vt_data['detected_downloaded_samples'][:3]:
                print(f"Sample Hash: {sample['sha256']}, Positives: {sample['positives']}/{sample['total']}")
    
    elif ioc_type == 'File Hash':
        print("\n--- VirusTotal Information ---")
        vt_data = result['VirusTotal']
        print(f"Response Code: {vt_data.get('response_code', 'None')}")
        print(f"Verbose Message: {vt_data.get('verbose_msg', 'None')}")
        
        if vt_data.get('response_code') == 0:
            print(f"Hash {ioc} is not yet scanned.")
        else:
            print(f"Detection Ratio: {vt_data.get('positives', 'None')}/{vt_data.get('total', 'None')}")
            print(f"Scan Date: {vt_data.get('scan_date', 'None')}")
    
    elif ioc_type == 'URL':
        print("\n--- VirusTotal Information ---")
        vt_data = result['VirusTotal']
        print(f"Response Code: {vt_data.get('response_code', 'None')}")
        print(f"Verbose Message: {vt_data.get('verbose_msg', 'None')}")
    
    elif ioc_type == 'Unknown':
        print("\nThis IOC could not be classified.")
    
    print("\n" + "="*80)

# Function to save the results to a CSV file for historical tracking
def save_results_to_csv(result, filename="historical_searches.csv"):
    ioc = result['IOC']
    ioc_type = result['Type']
    greynoise_data = result.get('GreyNoise', {})
    vt_data = result.get('VirusTotal', {})
    
    # If it's a file hash, extract the detection ratio from VirusTotal
    vt_response = vt_data.get('verbose_msg', 'None')
    if ioc_type == 'File Hash' and vt_data.get('response_code') != 0:
        vt_response = f"Detection Ratio: {vt_data.get('positives', 'None')}/{vt_data.get('total', 'None')}"
    
    # Add the scan date
    scan_date = datetime.now().strftime('%Y-%m-%d')
    
    # Prepare the record
    record = {
        'IOC': ioc,
        'Type': ioc_type,
        'GreyNoise_Noise': greynoise_data.get('noise', 'None'),
        'GreyNoise_RIOT': greynoise_data.get('riot', 'None'),
        'GreyNoise_Classification': greynoise_data.get('classification', 'None'),
        'VirusTotal_Response': vt_response,  # Store detection ratio if available
        'Scan Date': scan_date  # Add scan date to the CSV
    }
    
    # Check if the record already exists in the CSV
    if os.path.exists(filename):
        existing_data = pd.read_csv(filename)
        # Avoid duplicates by checking if the IOC already exists in the file
        if not ((existing_data['IOC'] == ioc) & (existing_data['Type'] == ioc_type)).any():
            df = pd.DataFrame([record])
            df.to_csv(filename, mode='a', header=False, index=False)
    else:
        df = pd.DataFrame([record])
        df.to_csv(filename, index=False)

# Main function with argparse to handle command line switches
def main():
    parser = argparse.ArgumentParser(description="IOC Analysis Script")
    parser.add_argument('-c', '--command', action='store_true', help="Manually enter IOCs")
    parser.add_argument('-l', '--list', type=str, help="Run analysis on IOCs from a text file")
    
    args = parser.parse_args()
    
    if args.command:
        try:
            while True:
                ioc = input("Enter IOC to analyze (Ctrl+C to exit): ").strip()
                if ioc:
                    result = analyze_ioc(ioc)
                    print_results(result)
                    save_results_to_csv(result)
        except KeyboardInterrupt:
            print("\nExiting...")
    
    elif args.list:
        file_path = args.list
        with open(file_path, 'r') as file:
            iocs = [line.strip() for line in file if not line.startswith("#") and line.strip()]
        for ioc in iocs:
            result = analyze_ioc(ioc)
            print_results(result)
            save_results_to_csv(result)
    else:
        print("Please specify either '-c' for manual input or '-l' for a list of IOCs.")

if __name__ == "__main__":
    main()
