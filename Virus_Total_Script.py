import requests
import time
import csv
import argparse

API_URL = 'https://www.virustotal.com/api/v3'
SCAN_URL = f'{API_URL}/files'
SCAN_URLS_URL = f'{API_URL}/urls'
IP_OR_HASH_REPORT_URL = f'{API_URL}/ip_addresses/%s'
URL_REPORT_URL = f'{API_URL}/urls/%s'
SCAN_WAIT_TIME = 15

def scan_file(file_path):
    with open(file_path, 'rb') as f:
        file_data = f.read()
    
    headers = {
        'x-apikey': args.api_key
    }
    
    files = {
        'file': ('file', file_data)
    }
    
    response = requests.post(SCAN_URL, headers=headers, files=files)
    if response.status_code == 200:
        return response.json()['data']['id']
    else:
        print(f'Scan failed for file: {file_path}')
        return None

def get_file_scan_result(scan_id):
    headers = {
        'x-apikey': args.api_key
    }
    
    response = requests.get(f'{SCAN_URL}/{scan_id}', headers=headers)
    if response.status_code == 200:
        return response.json()['data']['attributes']['last_analysis_results']
    else:
        print(f'Error getting scan result for file: {scan_id}')
        return None

def scan_url(url):
    headers = {
        'x-apikey': args.api_key
    }
    
    params = {
        'url': url
    }
    
    response = requests.post(SCAN_URLS_URL, headers=headers, params=params)
    if response.status_code == 200:
        return response.json()['data']['id']
    else:
        print(f'Scan failed for URL: {url}')
        return None

def get_url_scan_result(scan_id):
    headers = {
        'x-apikey': args.api_key
    }
    
    response = requests.get(f'{URL_REPORT_URL}/{scan_id}', headers=headers)
    if response.status_code == 200:
        return response.json()['data']['attributes']['last_analysis_results']
    else:
        print(f'Error getting scan result for URL: {scan_id}')
        return None

def scan_ip_or_hash(ip_or_hash):
    headers = {
        'x-apikey': args.api_key
    }
    
    response = requests.get(IP_OR_HASH_REPORT_URL % ip_or_hash, headers=headers)
    if response.status_code == 200:
        return response.json()['data']['attributes']['last_analysis_stats']
    else:
        print(f'Scan failed for IP or hash: {ip_or_hash}')
        return None

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Scan samples using VirusTotal API.')
    parser.add_argument('--api_key', type=str, required=True, help='VirusTotal API key')
    parser.add_argument('--file', type=str, nargs='+', help='File(s) to scan')
    parser.add_argument('--url', type=str, nargs='+', help='URL(s) to scan')
    parser.add_argument('--ip', type=str, nargs='+', help='IP address(es) or hash(es) to scan')
    parser.add_argument('--input', type=str, help='File containing URLs, IP addresses and hashes to scan')
    parser.add_argument('--output', type=str, default='scan_results.csv', help='Output CSV file')
    args = parser.parse_args()

    samples = []

    if args.file:
        for file_path in args.file:
            samples.append({'type': 'file', 'value': file_path})
    
    if args.url:
        for url in args.url:
            samples.append({'type': 'url', 'value': url})
    
    if args.ip:
        for ip_or_hash in args.ip:
            samples.append({'type': 'ip' if '.' in ip_or_hash else 'hash', 'value': ip_or_hash})
    
    if args.input:
        with open(args.input, 'r') as f:
            for line in f:
                line = line.strip()
                if line.startswith('http') or line.startswith('https'):
                    samples.append({'type': 'url', 'value': line})
                elif '.' in line:
                    samples.append({'type': 'ip', 'value': line})
                else:
                    samples.append({'type': 'hash', 'value': line})

    results = []
    for sample in samples:
        scan_id = None
        if sample['type'] == 'file':
            scan_id = scan_file(sample['value'])
        elif sample['type'] == 'url':
            scan_id = scan_url(sample['value'])
        elif sample['type'] == 'ip' or sample['type'] == 'hash':
            result = scan_ip_or_hash(sample['value'])
            if result:
                results.append({'type': sample['type'], 'value': sample['value'], 'results': result})
            continue
        
        if scan_id:
            time.sleep(SCAN_WAIT_TIME)
            scan_result = get_file_scan_result(scan_id) if sample['type'] == 'file' else get_url_scan_result(scan_id)
            if scan_result:
                results.append({'type': sample['type'], 'value': sample['value'], 'results': scan_result})

    with open(args.output, mode='w') as csv_file:
        fieldnames = ['type', 'value', 'result']
        writer = csv.DictWriter(csv_file, fieldnames=fieldnames)
        writer.writeheader()
        for result in results:
            writer.writerow({'type': result['type'], 'value': result['value'], 'result': result['results']})
    print(f'Scan results saved to {args.output}')
