import re
from email.utils import parsedate_to_datetime
import ipaddress
from ipwhois import IPWhois
import requests

def parse_email_headers(header_file):
    with open(header_file, 'r') as file:
        data = file.read()
    
    # Creating a dictionary to store the parsed header information
    header_dict = {}
    
    # Parsing key-value pairs from the email headers
    lines = data.splitlines()
    for line in lines:
        if ": " in line:
            key, value = line.split(": ", 1)
            header_dict[key.strip()] = value.strip()
    
    return header_dict

def analyze_headers(headers):
    analysis = {}
    
    # Extracting Message ID
    analysis['Message ID'] = headers.get('Message ID', 'Not Found')
    
    # Extracting Date and Converting to Datetime
    date_str = headers.get('Created on', 'Not Found')
    analysis['Created on'] = date_str
    try:
        analysis['Datetime'] = parsedate_to_datetime(date_str.split(' at ')[1].split('(')[0].strip())
    except Exception as e:
        analysis['Datetime'] = 'Invalid Date Format'

    # Extracting Sender
    analysis['From'] = headers.get('From', 'Not Found')
    
    # Extracting Recipient
    analysis['To'] = headers.get('To', 'Not Found')
    
    # Extracting Subject
    analysis['Subject'] = headers.get('Subject', 'Not Found')
    
    # SPF result
    spf_match = re.search(r'PASS with IP ([\d.]+)', headers.get('SPF', ''))
    analysis['SPF'] = spf_match.group(1) if spf_match else 'FAIL or Not Found'
    
    # DKIM result
    dkim_match = re.search(r"'PASS' with domain ([\w.-]+)", headers.get('DKIM', ''))
    analysis['DKIM'] = dkim_match.group(1) if dkim_match else 'FAIL or Not Found'
    
    # DMARC result
    dmarc_match = re.search(r"'PASS'", headers.get('DMARC', ''))
    analysis['DMARC'] = 'PASS' if dmarc_match else 'FAIL or Not Found'

    return analysis

def trace_route(headers):
    # Analyzing the Received headers for the email's journey
    route = []
    received_headers = [line for line in headers.splitlines() if line.startswith('Received:')]
    for received in received_headers:
        ip_match = re.search(r'\[(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\]', received)
        if ip_match:
            ip = ip_match.group(1)
            try:
                # Verify if it's a valid IP
                ipaddress.ip_address(ip)
                route.append(ip)
            except ValueError:
                continue
    return route

def get_ip_info(ip):
    try:
        obj = IPWhois(ip)
        res = obj.lookup_rdap()
        country = res['asn_country_code']
        city = res['network']['name']
        return country, city
    except Exception as e:
        return 'Unknown', 'Unknown'

def analyze_authentication(headers):
    issues = []
    if headers.get('SPF', '').startswith('FAIL'):
        issues.append('SPF validation failed.')
    if headers.get('DKIM', '').startswith('FAIL'):
        issues.append('DKIM validation failed.')
    if headers.get('DMARC', '').startswith('FAIL'):
        issues.append('DMARC validation failed.')
    
    # Check for potential spoofing
    from_domain = re.search(r'@([\w.-]+)', headers.get('From', ''))
    dkim_domain = headers.get('DKIM', '')
    if from_domain and dkim_domain and from_domain.group(1) != dkim_domain:
        issues.append(f"Potential spoofing detected: From domain ({from_domain.group(1)}) doesn't match DKIM domain ({dkim_domain}).")
    
    return issues

def visualize_analysis(analysis, route, issues):
    print("\n--- Email Header Analysis ---\n")
    for key, value in analysis.items():
        print(f"{key}: {value}")
    
    print("\n--- Route Analysis ---\n")
    if route:
        for ip in route:
            country, city = get_ip_info(ip)
            print(f"IP: {ip}, Location: {city}, {country}")
    else:
        print("No IP addresses found in the route.")
    
    print("\n--- Authentication Issues ---\n")
    if issues:
        for issue in issues:
            print(f"Issue: {issue}")
    else:
        print("No authentication issues detected.")
    
    print("\n------------------------------\n")

if __name__ == "__main__":
    header_file = "email_header.txt"
    headers = parse_email_headers(header_file)
    analysis = analyze_headers(headers)
    route = trace_route(header_file)
    issues = analyze_authentication(headers)
    visualize_analysis(analysis, route, issues)
