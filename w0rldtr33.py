import configparser
import re
import requests
import argparse
import pandas as pd
import os

# Load API keys from config.ini file
config = configparser.ConfigParser()
config.read('w0rldtr33.ini')

virustotal_api_key = config.get('API_KEYS', 'VIRUSTOTAL_API_KEY')
greynoise_api_key = config.get('API_KEYS', 'GREYNOISE_API_KEY')

# Regular expressions for different types of IOCs (IP, URL, file hash)
ip_regex = r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b"  # Matches IPv4 addresses
url_regex = r"https?://[^\s/$.?#].[^\s]*"  # Matches HTTP/HTTPS URLs
hash_regex = r"\b[a-fA-F0-9]{32,64}\b"  # Matches MD5 (32 characters) and SHA-1/SHA-256 (40/64 characters)

# Function to classify the type of IOC (IP, URL, File Hash, or Unknown)
def classify_ioc(ioc):
    if re.match(ip_regex, ioc):
        return 'IP Address'
    elif re.match(url_regex):
        return 'URL'
    elif re.match(hash_regex, ioc):
        return 'File Hash'
    else:
        return 'Unknown'

# Function to query VirusTotal for information about an IOC
def virustotal_lookup(ioc, ioc_type):
    if ioc_type == 'ip-address':
        url = f"https://www.virustotal.com/vtapi/v2/ip-address/report"
    elif ioc_type == 'url':
        url = f"https://www.virustotal.com/vtapi/v2/url/report"
    elif ioc_type == 'file':
        url = f"https://www.virustotal.com/vtapi/v2/file/report"
    else:
        return {'response_code': -1, 'verbose_msg': 'Unsupported IOC type'}
    
    params = {'apikey': virustotal_api_key, 'ip': ioc} if ioc_type == 'ip-address' else {'apikey': virustotal_api_key, 'resource': ioc}
    response = requests.get(url, params=params)
    return response.json()

# Function to query GreyNoise for information about an IP address
def greynoise_lookup(ip):
    url = f"https://api.greynoise.io/v3/community/{ip}"
    headers = {'key': greynoise_api_key}
    response = requests.get(url, headers=headers)
    return response.json()

# Function to analyze the list of IOCs and classify them
def analyze_iocs(iocs):
    results = []  
    for ioc in iocs:
        ioc_type = classify_ioc(ioc)
        
        if ioc_type == 'IP Address':
            print(f"Analyzing IP {ioc} with GreyNoise and VirusTotal...")
            greynoise_result = greynoise_lookup(ioc)  
            virustotal_result = virustotal_lookup(ioc, 'ip-address')  
            results.append({
                'IOC': ioc, 'Type': 'IP Address',
                'GreyNoise': greynoise_result,
                'VirusTotal': virustotal_result
            })
        
        elif ioc_type == 'URL':
            print(f"Analyzing URL {ioc} with VirusTotal...")
            virustotal_result = virustotal_lookup(ioc, 'url')
            results.append({
                'IOC': ioc, 'Type': 'URL',
                'VirusTotal': virustotal_result
            })
        
        elif ioc_type == 'File Hash':
            print(f"Analyzing file hash {ioc} with VirusTotal...")
            virustotal_result = virustotal_lookup(ioc, 'file')
            results.append({
                'IOC': ioc, 'Type': 'File Hash',
                'VirusTotal': virustotal_result
            })
        
        else:
            print(f"Unknown IOC type for {ioc}")
            results.append({'IOC': ioc, 'Type': 'Unknown'})
    
    return results

# ASCII Art Header
def print_ascii_art():
    print(r"""
 ██╗    ██╗ ██████╗ ██████╗ ██╗     ██████╗ ████████╗██████╗ ██████╗ ██████╗
  ██║    ██║██╔═████╗██╔══██╗██║     ██╔══██╗╚══██╔══╝██╔══██╗╚════██╗╚════██╗
  ██║ █╗ ██║██║██╔██║██████╔╝██║     ██║  ██║   ██║   ██████╔╝ █████╔╝ █████╔╝
  ██║███╗██║████╔╝██║██╔══██╗██║     ██║  ██║   ██║   ██╔══██╗ ╚═══██╗ ╚═══██╗
  ╚███╔███╔╝╚██████╔╝██║  ██║███████╗██████╔╝   ██║   ██║  ██║██████╔╝██████╔╝
   ╚══╝╚══╝  ╚═════╝ ╚═╝  ╚═╝╚══════╝╚═════╝    ╚═╝   ╚═╝  ╚═╝╚═════╝ ╚═════╝
    """)

# Function to print analysis results in a readable format
def print_results(results):
    print_ascii_art()
    print("\nAnalysis Results:\n" + "="*80)
    
    for result in results:
        ioc = result['IOC']
        ioc_type = result['Type']
        print("\n" + "="*80)
        print(f"\nIOC: {ioc}")
        print(f"Type: {ioc_type}")
        
        if ioc_type == 'IP Address':
            print("\n--- GreyNoise Information ---")
            greynoise_data = result['GreyNoise']
            print(f"IP: {greynoise_data.get('ip')}")
            print(f"Noise: {greynoise_data.get('noise')}")
            print(f"RIOT: {greynoise_data.get('riot')}")
            print(f"Classification: {greynoise_data.get('classification')}")
            print(f"Name: {greynoise_data.get('name')}")
            
            tags = greynoise_data.get('tags', [])
            if tags:
                print(f"Tags: {', '.join(tags)}")
            else:
                print(f"Tags: None")
            
            metadata = greynoise_data.get('metadata', {})
            print(f"Country: {metadata.get('country', 'Unknown')}")
            print(f"Organization: {metadata.get('organization', 'Unknown')}")
            print(f"ASN: {metadata.get('asn', 'Unknown')}")
            print(f"GreyNoise Link: {greynoise_data.get('link')}")
            print(f"Last Seen: {greynoise_data.get('last_seen')}")
            
            print("\n--- VirusTotal Information ---")
            vt_data = result['VirusTotal']
            print(f"Response Code: {vt_data.get('response_code')}")
            print(f"Verbose Message: {vt_data.get('verbose_msg')}")
            
            if 'detected_urls' in vt_data:
                print(f"Detected URLs: {len(vt_data['detected_urls'])}")
                for url_info in vt_data['detected_urls'][:3]:
                    print(f"URL: {url_info['url']}, Positives: {url_info['positives']}/{url_info['total']}")
            
            if 'detected_downloaded_samples' in vt_data:
                print(f"Detected Downloaded Samples: {len(vt_data['detected_downloaded_samples'])}")
                for sample in vt_data['detected_downloaded_samples'][:3]:
                    print(f"Sample Hash: {sample['sha256']}, Positives: {sample['positives']}/{sample['total']}")
        
        elif ioc_type == 'URL' or ioc_type == 'File Hash':
            print("\n--- VirusTotal Information ---")
            vt_data = result['VirusTotal']
            print(f"Response Code: {vt_data.get('response_code')}")
            print(f"Verbose Message: {vt_data.get('verbose_msg')}")
        
        elif ioc_type == 'Unknown':
            print("\nThis IOC could not be classified.")
    
    print("\n" + "="*80)

# Function to determine if IOC is malicious based on VirusTotal and GreyNoise
def is_malicious(greynoise_data, vt_data):
    # GreyNoise: If classification is malicious
    greynoise_malicious = greynoise_data.get('classification') == 'malicious'
    
    # VirusTotal: If VirusTotal reports detections
    vt_malicious = vt_data.get('response_code') == 1 and ('detected_urls' in vt_data or 'detected_downloaded_samples' in vt_data)
    
    return greynoise_malicious or vt_malicious

# Function to save the results to a CSV file for historical tracking
def save_results_to_csv(results, filename="historical_searches.csv"):
    records = []
    for result in results:
        ioc = result['IOC']
        ioc_type = result['Type']
        greynoise_data = result.get('GreyNoise', {})
        vt_data = result.get('VirusTotal', {})
        
        # Determine if the IOC is malicious
        malicious = is_malicious(greynoise_data, vt_data)
        
        # Extract relevant data for CSV
        record = {
            'IOC': ioc,
            'Type': ioc_type,
            'GreyNoise_Noise': greynoise_data.get('noise'),
            'GreyNoise_RIOT': greynoise_data.get('riot'),
            'GreyNoise_Classification': greynoise_data.get('classification'),
            'VirusTotal_Response': vt_data.get('verbose_msg'),
            'Malicious': malicious  # Common column for malicious
        }
        records.append(record)
    
    df = pd.DataFrame(records)
    
    # If the file already exists, append without writing the header again
    if os.path.exists(filename):
        df.to_csv(filename, mode='a', header=False, index=False)
    else:
        df.to_csv(filename, index=False)

# Function to load IOCs from a text file (ignoring lines starting with "#")
def get_iocs_from_file(file_path):
    with open(file_path, 'r') as file:
        iocs = [line.strip() for line in file if not line.startswith("#") and line.strip()]
    return iocs

# Main function with argparse to handle command line switches
def main():
    parser = argparse.ArgumentParser(description="IOC Analysis Script")
    parser.add_argument('-c', '--command', action='store_true', help="Manually enter IOCs")
    parser.add_argument('-l', '--list', type=str, help="Run analysis on IOCs from a text file")
    
    args = parser.parse_args()
    
    if args.command:
        iocs = []
        print_ascii_art()
        print("Enter IOCs one by one. Type 'done' when finished:")
        while True:
            ioc = input("> ").strip()
            if ioc.lower() == 'done':
                break
            iocs.append(ioc)
        
    elif args.list:
        file_path = args.list
        iocs = get_iocs_from_file(file_path)
        print_ascii_art()
    
    else:
        print("Please specify either '-c' for manual input or '-l' for a list of IOCs.")
        return

    # Analyze and print results
    results = analyze_iocs(iocs)
    print_results(results)

    # Save results to CSV
    save_results_to_csv(results)

if __name__ == "__main__":
    main()
