import re
import requests
import csv
import json
import os
from dotenv import load_dotenv
import parsing
import siem
import colorama
import ipaddress
from fpdf import FPDF
from io import StringIO


load_dotenv(override=True)

abuseip = os.getenv("abuseipdbkey")

args = parsing.arguments()
token = os.getenv("githubtoken")

def reg(arq):
    reg = []
    with open(arq, 'r', encoding="utf8") as outfile:
        reader = csv.reader(outfile)
        for raw in reader:
            for cell in raw: 
                matches = re.findall(r'((?:HKEY_LOCAL_MACHINE|HKEY_CURRENT_USER|HKEY_CLASSES_ROOT|HKEY_USERS|HKEY_CURRENT_CONFIG|HKLM|HKCU|HKCR|HKU|HKCC)(?:\\[\w\dçÇ{}$.\- ]*)*(?:\s*\n\s*\\[\w\dçÇ{}$.\- ]*)*)', cell, re.DOTALL)

                reg.extend(matches)
    return set(reg)


def cve(arq):
    cve = []
    with open(arq, 'r', encoding="utf8") as outfile:
        full = outfile.read()
        full = full.replace('\n', '')
        for raw in full:
            for cell in raw:
                matches = re.findall(r'CVE-[\d]{4}-[\d]{,5}|cve-[\d]{4}-[\d]{,5}', full)
                cve.extend(matches)
    return set (cve)


def ip(arq):
    ips = []
    with open(arq, 'r', encoding="utf8") as outfile:
        reader = csv.reader(outfile)
        for raw in reader:
            for cell in raw:
                cell = cell.replace('[', '').replace(']', '')
                matches = re.findall(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', cell)
                ips.extend(matches)
                ip2 = []
                for valid in ips:
                    try:
                        ipaddress.ip_address(valid)
                        ip2.append(valid)
                    except ValueError:
                        pass
    return set(ip2) 


def md5(arq):
    hashes = []
    with open(arq, 'r', encoding="utf8") as outfile:
        reader = csv.reader(outfile)
        for raw in reader:
            for cell in raw:
                matches = re.findall(r'\b[0-9a-f]{32}\b', cell)
                hashes.extend(matches)
    return set(hashes)


def sha1(arq):
    hashes = []
    with open(arq, 'r', encoding="utf8") as outfile:
        reader = csv.reader(outfile)
        for raw in reader:
            for cell in raw:
                matches = re.findall(r'\b[0-9a-f]{40}\b', cell)
                hashes.extend(matches)
    return set(hashes)
    

def sha256(arq):
    hashes = []
    with open(arq, 'r', encoding="utf8") as outfile:
        reader = csv.reader(outfile)
        for raw in reader:
            for cell in raw:
                matches = re.findall(r'\b[0-9a-fA-F]{64}\b', cell)
                hashes.extend(matches)
    return set(hashes)


def domain(arq):
    domains = []
    tld = ['.com','.net','.br','.onion','.org','.gov', '.de', '.at', '.co','.link','.sh','.nz','.ua','.ch','.us','.pl', 'xyz','io','uk','kg']
    with open(arq, 'r', encoding="utf8") as outfile:
        reader = csv.reader(outfile)
        for raw in reader:
            for cell in raw:
                cell = cell.replace('[', '').replace(']', '')
                matches = re.findall(r'\b(?:[a-zA-Z0-9-]+\.){1,}[a-zA-Z]{2,}\b', cell)
                for match in matches:
                    for index in tld:
                        if match.endswith(index):
                            domains.append(match)
    return set(domains)


def artifact(arq):
    process = []
    process_extension = ['.exe','.dll','.py','.vbs','.ps1','.bin','.bat','.wsf','.bk','.sys','.tmp']
    with open(arq, 'r', encoding="utf8") as outfile:
        reader = csv.reader(outfile)
        for raw in reader:
            for cell in raw:
                matches = re.findall(r'[a-zA-Z0-9_\-\.]+?\.[a-zA-Z0-9]+', cell)
                for match in matches:
                    for index in process_extension:
                        if match.endswith(index):
                            process.append(match)
    return set(process)


def email(arq):
    emails = []
    with open(arq, 'r', encoding="utf8") as outfile:
        reader = csv.reader(outfile)
        for raw in reader:
            for cell in raw:
                cell = cell.replace('[', '').replace(']', '')
                matches = re.findall(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', cell)
                emails.extend(matches)
    return set(emails)


def find_exploit_cve(cve):
    url = "https://gitlab.com/exploit-database/exploitdb/-/raw/main/files_exploits.csv?ref_type=heads"

    try:
        response = requests.get(url, timeout=10)
        response.raise_for_status()

        csv_data = StringIO(response.text)
        reader = csv.reader(csv_data)

        for row in reader:
            for cell in row:
                if cve.strip() in cell:
                    exploit_id = row[0]
                    return f"https://www.exploit-db.com/exploits/{exploit_id}"

        return None

    except requests.RequestException as e:
        print(f"Error accessing Exploit-DB: {e}")
        return None


def cve_with_report(arguments):
    conv = list(cve(arguments.input))
    return conv  


def ip_scnx(arguments):

    if not ip(arguments.input):
        print(colorama.Fore.RED + '[!] Not found ip address' + colorama.Style.RESET_ALL)
    else:
        records_ip = []
        scnx_source_address = siem.scnx_source_address()
        scnx_destination_address = siem.scnx_destination_adrress()
        source_only = siem.scnx_source_address_only()
        destination_only = siem.scnx_destination_address_only()
        stats = siem.scnx_stats()
        found_ip = ip(args.input)
        
        for index in found_ip:
            records_ip.append(index)

            if args.include:
                        records_ip.extend(args.include)
                        records_ip = list(set(records_ip))
                
            if args.remove:
                records_ip = [item for item in records_ip if item not in args.remove]

        arrow = colorama.Fore.RED + '    ↳  ' + colorama.Style.RESET_ALL
        print(colorama.Fore.GREEN + '[+] AV / EDR / SO\n' + colorama.Style.RESET_ALL)
        print(colorama.Fore.RED + '[+] This query seeks to identify IP addresses as the source of communication' + colorama.Style.RESET_ALL)
        print(arrow, f'{scnx_source_address} ({', '.join(records_ip)})\n')
        print(colorama.Fore.RED + '[+] This query seeks to identify IP addresses as the communication destination.' + colorama.Style.RESET_ALL)
        print(arrow, f'{scnx_destination_address} ({', '.join(records_ip)})\n')
        print(colorama.Fore.RED + '[+] This query seeks to identify IP addresses as the source or destination of the communication' + colorama.Style.RESET_ALL)
        print(arrow, f'{scnx_source_address} ({', '.join(records_ip)}) {colorama.Fore.BLUE}OR{colorama.Style.RESET_ALL} {scnx_destination_address} ({', '.join(records_ip)})\n')
        print(colorama.Fore.RED + '[+] This query seeks to identify IP addresses as the source or destination of the communication' + colorama.Style.RESET_ALL)
        print(arrow, f'{scnx_source_address} ({', '.join(records_ip)}) {colorama.Fore.BLUE}OR{colorama.Style.RESET_ALL} {scnx_destination_address} ({', '.join(records_ip)}) {stats}{source_only}\n') 
        print(colorama.Fore.RED + '[+] This query seeks to identify IP addresses as the source or destination of the communication' + colorama.Style.RESET_ALL) 
        print(arrow, f'{scnx_source_address} ({', '.join(records_ip)}) {colorama.Fore.BLUE}OR{colorama.Style.RESET_ALL} {scnx_destination_address} ({', '.join(records_ip)}) {stats}{destination_only}\n')


def ip_scnx_l(arguments):

    if not ip(arguments.input):
        print(colorama.Fore.RED + '[!] Not found ip address' + colorama.Style.RESET_ALL )
    else:       
            records_ip = []
            scnx_source_address = siem.scnx_source_address()
            scnx_destination_address = siem.scnx_destination_adrress()
            source_only = siem.scnx_source_address_only()
            destination_only = siem.scnx_destination_address_only()
            stats = siem.scnx_stats()
            found_ip = ip(args.input)                     

            while len(found_ip) >= 2:

                for index in found_ip:
                    records_ip.append(index)

                    if args.include:
                        records_ip.extend(args.include)
                        records_ip = list(set(records_ip))
                
                    if args.remove:
                        records_ip = [item for item in records_ip if item not in args.remove]

                    meadle = len(records_ip) // 2
                    new1 = records_ip[:meadle]
                    new2 = records_ip[meadle:]

                arrow = colorama.Fore.RED + '    ↳  ' + colorama.Style.RESET_ALL
                print(colorama.Fore.GREEN + '[+] AV / EDR / SO\n' + colorama.Style.RESET_ALL)
                print(colorama.Fore.RED + '[-] This query seeks to identify IP addresses as the source of communication\n' + colorama.Style.RESET_ALL)
                print(arrow, f'{scnx_source_address} ({', '.join(new1)})')
                print(arrow, f'{scnx_source_address} ({', '.join(new2)})\n')
                print(colorama.Fore.RED + '[-] This query seeks to identify IP addresses as the communication destination\n' + colorama.Style.RESET_ALL)
                print(arrow, f'{scnx_destination_address} ({', '.join(new1)})')
                print(arrow, f'{scnx_destination_address} ({', '.join(new2)})\n')
                print(colorama.Fore.RED + '[-] This query seeks to identify IP addresses as the source or destination of the communication\n' + colorama.Style.RESET_ALL)
                print(arrow, f'{scnx_source_address} ({', '.join(new1)}) {colorama.Fore.BLUE}OR{colorama.Style.RESET_ALL} {scnx_destination_address} ({', '.join(new1)})')
                print(arrow, f'{scnx_source_address} ({', '.join(new2)}) {colorama.Fore.BLUE}OR{colorama.Style.RESET_ALL} {scnx_destination_address} ({', '.join(new2)})\n')
                print(colorama.Fore.RED + '[-] This query seeks to identify IP addresses as the source or destination of communication organized by source address\n' + colorama.Style.RESET_ALL)
                print(arrow, f'{scnx_source_address} ({', '.join(new1)}) {colorama.Fore.BLUE}OR{colorama.Style.RESET_ALL} {scnx_destination_address} ({', '.join(new1)}) {stats}{source_only}')
                print(arrow, f'{scnx_source_address} ({', '.join(new2)}) {colorama.Fore.BLUE}OR{colorama.Style.RESET_ALL} {scnx_destination_address} ({', '.join(new2)}) {stats}{source_only}\n')
                print(colorama.Fore.RED + '[-] This query seeks to identify IP addresses as the source or destination of communication organized by destination address\n' + colorama.Style.RESET_ALL)
                print(arrow, f'{scnx_source_address} ({', '.join(new1)}) {colorama.Fore.BLUE}OR{colorama.Style.RESET_ALL} {scnx_destination_address} ({', '.join(new1)}) {stats}{destination_only}')
                print(arrow, f'{scnx_source_address} ({', '.join(new2)}) {colorama.Fore.BLUE}OR{colorama.Style.RESET_ALL} {scnx_destination_address} ({', '.join(new2)}) {stats}{destination_only}\n')
            
                break

            if len(found_ip) < 2:                    
                print(colorama.Fore.RED + 'The -l or --l argument only accepts values ​​equal to or greater than 2, possibly the source does not have more than one value or cannot be extracted correctly\n' + colorama.Style.RESET_ALL)
    
def ip_rsa(arguments):

    if not ip(arguments.input):
        print(colorama.Fore.RED + '[!] Not found ip address' + colorama.Style.RESET_ALL)
    else:        
        records_ip = []
        rsa_src_adress = siem.rsa_source_address()
        rsa_dst_adress = siem.rsa_destination_adress()
        found_ip = ip(args.input)

        for index in found_ip:
            records_ip.append(index)

        arrow = colorama.Fore.RED + '    ↳  ' + colorama.Style.RESET_ALL
        print(colorama.Fore.GREEN + '[+] AV / EDR / SO\n' + colorama.Style.RESET_ALL)
        color = ' ||' + colorama.Fore.BLUE + ' ip.src = ' + colorama.Style.RESET_ALL
        print(colorama.Fore.RED + '[+] This query seeks to identify IP addresses as the source of communication' + colorama.Style.RESET_ALL)
        print(arrow, f'{rsa_src_adress} {color.join(records_ip)} \n')
        color = ' ||' + colorama.Fore.BLUE + ' ip.dst = ' + colorama.Style.RESET_ALL
        print(colorama.Fore.RED + '[+] This query seeks to identify IP addresses as the communication destination.' + colorama.Style.RESET_ALL)
        print(arrow, f'{rsa_dst_adress} {color.join(records_ip)} \n')
        color = ' ||' + colorama.Fore.BLUE + ' ip.src = ' + colorama.Style.RESET_ALL
        print(colorama.Fore.RED + '[+] This query seeks to identify IP addresses as the source or destination of the communication' + colorama.Style.RESET_ALL)
        print(arrow, f'{rsa_src_adress} {color.join(records_ip)} {colorama.Fore.BLUE} || {colorama.Style.RESET_ALL}', end='')
        color = ' || ' + colorama.Fore.BLUE + ' ip.dst = ' + colorama.Style.RESET_ALL
        print(rsa_dst_adress, color.join(records_ip))


def ip_rsa_l(arguments):

    if not ip(arguments.input):
        print(colorama.Fore.RED + '[!] Not found ip address' + colorama.Style.RESET_ALL)
    else:
        
        records_ip = []
        rsa_src_adress = siem.rsa_source_address()
        rsa_dst_adress = siem.rsa_destination_adress()
        found_ip = ip(args.input)

        while len(found_ip) >= 2:

            for index in found_ip:
                records_ip.append(index)
                meadle = len(records_ip) // 2
                new1 = records_ip[:meadle]
                new2 = records_ip[meadle:]

            arrow = colorama.Fore.RED + '    ↳  ' + colorama.Style.RESET_ALL
            print(colorama.Fore.GREEN + '[+] AV / EDR / SO\n' + colorama.Style.RESET_ALL)
            print(colorama.Fore.RED + '[-] This query seeks to identify IP addresses as the source of communication\n' + colorama.Style.RESET_ALL)
            color = ' ||' + colorama.Fore.BLUE + ' ip.src = ' + colorama.Style.RESET_ALL
            print(arrow, f'{rsa_src_adress} {color.join(new1)}')
            color = ' ||' + colorama.Fore.BLUE + ' ip.src = ' + colorama.Style.RESET_ALL
            print(arrow, f'{rsa_src_adress} {color.join(new2)} \n')
            print(colorama.Fore.RED + '[-] This query seeks to identify IP addresses as the destination of communication\n' + colorama.Style.RESET_ALL)
            color = ' ||' + colorama.Fore.BLUE + ' ip.dst = ' + colorama.Style.RESET_ALL
            print(arrow, f'{rsa_dst_adress} {color.join(new1)}')
            color = ' ||' + colorama.Fore.BLUE + ' ip.dst = ' + colorama.Style.RESET_ALL
            print(arrow, f'{rsa_dst_adress} {color.join(new2)} \n')
            print(colorama.Fore.RED + '[-] This query seeks to identify IP addresses as the source or destination of the communication\n' + colorama.Style.RESET_ALL)
            color = ' ||' + colorama.Fore.BLUE + ' ip.src = ' + colorama.Style.RESET_ALL
            print(arrow, f'{rsa_src_adress} {color.join(new1)} {colorama.Fore.BLUE} || {colorama.Style.RESET_ALL}', end='')
            color = ' ||' + colorama.Fore.BLUE + ' ip.dst = ' + colorama.Style.RESET_ALL
            print(f'{rsa_dst_adress} {color.join(new1)} {colorama.Fore.BLUE} {colorama.Style.RESET_ALL}')
            color = ' ||' + colorama.Fore.BLUE + ' ip.src = ' + colorama.Style.RESET_ALL
            print(arrow, f'{rsa_src_adress} {color.join(new2)} {colorama.Fore.BLUE} || {colorama.Style.RESET_ALL}', end='')
            color = ' ||' + colorama.Fore.BLUE + ' ip.dst = ' + colorama.Style.RESET_ALL
            print(f'{rsa_dst_adress} {color.join(new2)} {colorama.Fore.BLUE} {colorama.Style.RESET_ALL} \n')
            
            break
        
        if len(found_ip) < 2:                    
                print(colorama.Fore.RED + 'The -l or --l argument only accepts values ​​equal to or greater than 2, possibly the source does not have more than one value or cannot be extracted correctly\n' + colorama.Style.RESET_ALL)


def ip_with_reputation(arguments):
    if not ip(arguments.input):
        print(colorama.Fore.RED + '[!] Not found ip address' + colorama.Style.RESET_ALL)
        return

    print(colorama.Fore.GREEN + '[+] IP Address Reputation Check on AbuseIPDB\n' + colorama.Style.RESET_ALL)

    url = 'https://api.abuseipdb.com/api/v2/check'
    headers = {
        'Accept': 'application/json',
        'Key': abuseip
    }

    querystring = {
        'ipAddress': '0.0.0.0',
        'maxAgeInDays': '90'
    }

    ip_parsing = list(set(ip(arguments.input)))

    print(f"{'IP':<17} {'Score':<9} {'Domínios Associados'}")
    print("-" * 50)

    for index in ip_parsing:
        querystring["ipAddress"] = index

        try:
            response = requests.get(url=url, headers=headers, params=querystring)
            data = response.json()['data']
            address = data['ipAddress']
            rep = data['abuseConfidenceScore']
            dns = ', '.join(data['hostnames']) if data['hostnames'] else '-'
        except KeyError:
            print(colorama.Fore.RED + "[!] Erro com a chave da API ou resposta inesperada." + colorama.Style.RESET_ALL)
            break

        if rep <= 25:
            color = colorama.Fore.GREEN
        elif rep <= 50:
            color = colorama.Fore.BLUE
        elif rep <= 75:
            color = colorama.Fore.YELLOW
        else:
            color = colorama.Fore.RED

        rep_formatado = f"{rep}%"
        rep_alinhado = f"{rep_formatado:<9}"

        rep_colorido = color + rep_alinhado + colorama.Style.RESET_ALL

        print(f"{address:<17} {rep_colorido} {dns}")



def ip_only(arguments):

    if not ip(arguments.input):
        print(colorama.Fore.RED + '[!] Not found ip address' + colorama.Style.RESET_ALL)
    else:     
        print(colorama.Fore.GREEN + '[+] IPs\n' + colorama.Style.RESET_ALL)   
        found_ip = ip(args.input)
        for index in set(found_ip):
            print(index)


def domain_scnx_l(arguments):
       
    if not domain(arguments.input):
        print('[!] Not found domain address' + colorama.Style.RESET_ALL)
    else:

        records_domain = []
        scnx_request_url = siem.scnx_request_url()
        scnx_request_only = siem.scnx_request_url_only()
        scnx_email_recipient_domain = siem.scnx_email_recipient_domain()
        scnx_email_recipient_domain_only = siem.scnx_email_recipient_domain_only()
        scnx_fqdn = siem.scnx_fqdn()
        scnx_fqdn_only = siem.scnx_fqdn_only()
        scnx_root_domain = siem.scnx_root_domain()
        scnx_root_domain_only = siem.scnx_root_domain_only()
        stats = siem.scnx_stats()
        found_domain = domain(args.input)

        for index in found_domain:
            records_domain.append(index)

            if args.include:
                    records_domain.extend(args.include)
                    records_domain = list(set(records_domain))
                
            if args.remove:
                records_domain = [item for item in records_domain if item not in args.remove]

            meadle = len(records_domain) // 2
            new1 = records_domain[:meadle]
            new2 = records_domain[meadle:]

        domain_request_url_without = f' OR {scnx_request_only} contains '
        domain_fqdn_without = f' OR {scnx_fqdn_only} contains '
        domain_root_domain_without = f' OR {scnx_root_domain_only} contains '
        domain_email_recipient_domain_without = f' OR {scnx_email_recipient_domain_only} contains '                
        
        arrow = colorama.Fore.RED + '    ↳  ' + colorama.Style.RESET_ALL
        print(colorama.Fore.GREEN + '[+] NGFW / WAF / PROXY\n' + colorama.Style.RESET_ALL)    
        print(colorama.Fore.RED + '[-] This query seeks to identify domain addresses\n' + colorama.Style.RESET_ALL)    
        print(arrow, f'{scnx_request_url} ({', '.join(new1)})')
        print(arrow, f'{scnx_request_url} ({', '.join(new2)})')
        print(arrow, f'{scnx_fqdn} ({', '.join(new1)})')
        print(arrow, f'{scnx_fqdn} ({', '.join(new2)})')
        print(arrow, f'{scnx_root_domain} ({', '.join(new1)})')
        print(arrow,f'{scnx_root_domain} ({', '.join(new2)})\n')
        print(colorama.Fore.RED + '[-]This query seeks to identify queried values ​​organized by the values ​​of the queried metakey\n' + colorama.Style.RESET_ALL)  
        print(arrow, f'{scnx_request_url} ({', '.join(new1)}) {stats}{scnx_request_only}')
        print(arrow, f'{scnx_request_url} ({', '.join(new2)}) {stats}{scnx_request_only}')
        print(arrow, f'{scnx_fqdn} ({', '.join(new1)}) {stats}{scnx_fqdn_only}')
        print(arrow, f'{scnx_fqdn} ({', '.join(new2)}) {stats}{scnx_fqdn_only}')
        print(arrow, f'{scnx_root_domain} ({', '.join(new1)}) {stats}{scnx_root_domain_only}')
        print(arrow, f'{scnx_root_domain} ({', '.join(new2)}) {stats}{scnx_root_domain_only}\n')  
        print(colorama.Fore.RED + '[-] This query seeks to identify the value queried within a string using the "CONTAINS" operator\n' + colorama.Style.RESET_ALL)
        print(arrow, f'{scnx_request_only} contains {domain_request_url_without.join(new1)}')
        print(arrow, f'{scnx_request_only} contains {domain_request_url_without.join(new2)}')
        print(arrow, f'{scnx_fqdn_only} contains {domain_fqdn_without.join(new1)}')
        print(arrow, f'{scnx_fqdn_only} contains {domain_fqdn_without.join(new2)}')
        print(arrow, f'{scnx_root_domain_only} contains {domain_root_domain_without.join(new1)}')
        print(arrow, f'{scnx_root_domain_only} contains {domain_root_domain_without.join(new2)}\n')
        print(colorama.Fore.GREEN + '[+] EXCHANGE\n' + colorama.Style.RESET_ALL) 
        print(colorama.Fore.RED + '[-] This query seeks to identify domain addresses using the requesturl recipientdomain metacharacter used in email solution data sources\n' + colorama.Style.RESET_ALL) 
        print(arrow, f'{scnx_email_recipient_domain} ({', '.join(new1)})')
        print(arrow, f'{scnx_email_recipient_domain} ({', '.join(new2)})\n')
        print(colorama.Fore.RED + '[-]This query seeks to identify queried values ​​organized by the values ​​of the queried metakey\n' + colorama.Style.RESET_ALL)        
        print(arrow, f'{scnx_email_recipient_domain} ({', '.join(new1)}) {stats}{scnx_email_recipient_domain_only}')
        print(arrow, f'{scnx_email_recipient_domain} ({', '.join(new2)}) {stats}{scnx_email_recipient_domain_only}\n')
        print(colorama.Fore.RED + '[-] This query seeks to identify the value queried within a string using the "CONTAINS" operator\n' + colorama.Style.RESET_ALL)        
        print(arrow, f'{scnx_email_recipient_domain_only} contains {domain_email_recipient_domain_without.join(new1)}')
        print(arrow, f'{scnx_email_recipient_domain_only} contains {domain_email_recipient_domain_without.join(new2)}')        


def domain_scnx(arguments):

    if not domain(arguments.input):
        print(colorama.Fore.RED + '[!] Not found domain address' + colorama.Style.RESET_ALL)
    else:
        records_domain = []
        scnx_request_url = siem.scnx_request_url()
        scnx_request_only = siem.scnx_request_url_only()
        scnx_email_recipient_domain = siem.scnx_email_recipient_domain()
        scnx_email_recipient_domain_only = siem.scnx_email_recipient_domain_only()
        scnx_fqdn = siem.scnx_fqdn()
        scnx_fqdn_only = siem.scnx_fqdn_only()
        scnx_root_domain = siem.scnx_root_domain()
        scnx_root_domain_only = siem.scnx_root_domain_only()
        stats = siem.scnx_stats()
        found_domain = domain(args.input)

        for index in found_domain:
            records_domain.append(index)

            if args.include:
                    records_domain.extend(args.include)
                    records_domain = list(set(records_domain))
                
            if args.remove:
                records_domain = [item for item in records_domain if item not in args.remove]

        print(colorama.Fore.GREEN + '[-] NGFW / WAF / PROXY\n' + colorama.Style.RESET_ALL)
        arrow = colorama.Fore.RED + '    ↳  ' + colorama.Style.RESET_ALL
        print(colorama.Fore.YELLOW + '[!] Please note that this query considers exact values. Some data sources address this information with more details than just the domain/subdomain. For example: "www.google.com/file?=" in this case it may be more interesting to use the "contains" query suggestion\n' + colorama.Style.RESET_ALL)
        print(colorama.Fore.RED + '[-] This query seeks to identify domain addresses\n' + colorama.Style.RESET_ALL)        
        print(arrow, f'{scnx_request_url} ({', '.join(records_domain)})')
        print(arrow, f'{scnx_fqdn} ({', '.join(records_domain)})')
        print(arrow, f'{scnx_root_domain} ({', '.join(records_domain)})\n')
        print(colorama.Fore.RED + '[-] This query seeks to identify the value queried within a string using the "CONTAINS" operator\n' + colorama.Style.RESET_ALL)
        domain_request_url_without =  f' {colorama.Fore.BLUE} OR {scnx_request_only} {colorama.Fore.BLUE} contains ' + colorama.Style.RESET_ALL
        print(arrow, f'{scnx_request_only} {colorama.Fore.BLUE} contains {colorama.Style.RESET_ALL} {domain_request_url_without.join(records_domain)}')
        domain_fqdn_without = f' {colorama.Fore.BLUE} OR {scnx_fqdn_only} {colorama.Fore.BLUE} contains ' + colorama.Style.RESET_ALL
        print(arrow, f'{scnx_fqdn_only} contains {domain_fqdn_without.join(records_domain)}')
        domain_root_domain_without = f' {colorama.Fore.BLUE} OR {scnx_root_domain_only} {colorama.Fore.BLUE} contains ' + colorama.Style.RESET_ALL
        print(arrow, f'{scnx_root_domain_only} contains {domain_root_domain_without.join(records_domain)}')
        domain_email_recipient_domain_without = f' {colorama.Fore.BLUE} OR {scnx_email_recipient_domain_only} contains ' + colorama.Style.RESET_ALL      
        print(arrow, f'{scnx_email_recipient_domain_only} contains {domain_email_recipient_domain_without.join(records_domain)}\n')
        print(colorama.Fore.RED + '[-] This query seeks to identify queried values ​​organized by the values ​​of the queried metakey.\n' + colorama.Style.RESET_ALL)
        print(arrow, f'{scnx_request_url} ({', '.join(records_domain)}) {stats}{scnx_request_only}')
        print(arrow, f'{scnx_fqdn} ({', '.join(records_domain)}) {stats}{scnx_fqdn_only}')
        print(arrow, f'{scnx_root_domain} ({', '.join(records_domain)}) {stats}{scnx_root_domain_only}\n')        
        print(colorama.Fore.GREEN + '[+] EXCHANGE\n' + colorama.Style.RESET_ALL)
        print(colorama.Fore.RED + '[-] This query seeks to identify domain addresses using the requesturl recipientdomain metacharacter used in email solution data sources\n' + colorama.Style.RESET_ALL) 
        print(arrow, f'{scnx_email_recipient_domain} ({', '.join(records_domain)})\n')
        print(colorama.Fore.RED + '[-] This query seeks to identify queried values ​​organized by the values ​​of the queried metakey.\n' + colorama.Style.RESET_ALL)
        print(arrow, f'{scnx_email_recipient_domain} ({', '.join(records_domain)}) {stats}{scnx_email_recipient_domain_only}\n')        
        

def domain_rsa_l(arguments):

    if arguments.input and arguments.domain and arguments.rsa and arguments.l:

        if not domain(arguments.input):
            print(colorama.Fore.RED + '[!] Not found domain address' + colorama.Style.RESET_ALL)
        else:   
            records_domain = []
            rsa_url = siem.rsa_url()
            found_domain = domain(args.input)

            for index in found_domain:
                records_domain.append("'" + index + "'")
                meadle = len(records_domain) // 2
                new1 = records_domain[:meadle]
                new2 = records_domain[meadle:]

                
            print(colorama.Fore.GREEN + '[+] NGFW / WAF / PROXY\n' + colorama.Style.RESET_ALL)
            color = ' ||' + colorama.Fore.BLUE + ' url = ' + colorama.Style.RESET_ALL 
            print(f'{rsa_url} {color.join(new1)}\n')
            color = ' ||' + colorama.Fore.BLUE + ' url = ' + colorama.Style.RESET_ALL
            print(f'{rsa_url} {color.join(new2)}')

    
def domain_rsa(arguments):
    
    if not domain(arguments.input):
        print(colorama.Fore.RED + '[!] Not found domain address' + colorama.Style.RESET_ALL)
    else:   
        records_domain = []
        rsa_url = siem.rsa_url()
        found_domain = domain(args.input)

        for index in found_domain:
            records_domain.append("'" + index + "'")
            
        print(colorama.Fore.GREEN + '[+] NGFW / WAF / PROXY\n' + colorama.Style.RESET_ALL)
        color = ' ||' + colorama.Fore.BLUE + ' url = ' + colorama.Style.RESET_ALL
        print(f'{rsa_url} {color.join(records_domain)}')

def domain_only(arguments):
        
    if not domain(arguments.input):
        print(colorama.Fore.RED + '[!] Not found domain address' + colorama.Style.RESET_ALL)
    else:   
        print(colorama.Fore.GREEN + '[+] Domains\n' + colorama.Style.RESET_ALL)   
        found_domain = domain(args.input)
        for index in set(found_domain):
            print(index)


def artifact_scnx_l(arguments):

    if not artifact(arguments.input):
        print(colorama.Fore.RED + '[!] Not found artifact' + colorama.Style.RESET_ALL)
    else:        
        records_artifact = []
        scnx_sourceprocessname = siem.scnx_source_process_name()
        scnx_source_process_name_only = siem.scnx_source_process_name_only()
        scnx_destination_process_name = siem.scnx_destination_process_name()
        scnx_destination_process_name_only = siem.scnx_destination_process_name_only()
        scnx_filename = siem.scnx_file_name()
        scnx_file_name_only = siem.scnx_file_name_only()
        found_artifact = artifact(args.input)
        command_line_only = siem.scnx_command_line_only()
        childprocesscommandline_only = siem.childprocesscommandline_only()
        stats = siem.scnx_stats()

        while len(found_artifact) >= 2:
            
            found_artifact = artifact(args.input)
            for index in found_artifact:
                records_artifact.append(index)

                if args.include:
                    records_artifact.extend(args.include)
                    records_artifact = list(set(records_artifact))
                
                if args.remove:
                    records_artifact = [item for item in records_artifact if item not in args.remove]

                meadle = len(records_artifact) // 2
                new1 = records_artifact[:meadle]
                new2 = records_artifact[meadle:]

            arrow = colorama.Fore.RED + '    ↳  ' + colorama.Style.RESET_ALL
            print(colorama.Fore.GREEN + '[+] Windows / Linux\n' + colorama.Style.RESET_ALL)
            print(colorama.Fore.RED + '[-] This query seeks to identify the process acting as the parent process' + colorama.Style.RESET_ALL)
            print(arrow, f'{scnx_sourceprocessname} ({', '.join(new1)})')
            print(arrow, f'{scnx_sourceprocessname} ({', '.join(new2)})\n')
            print(colorama.Fore.RED + '[-] This query seeks to identify the process acting as the child process' + colorama.Style.RESET_ALL)
            print(arrow, f'{scnx_destination_process_name} ({', '.join(new1)})')
            print(arrow, f'{scnx_destination_process_name} ({', '.join(new2)})\n')
            print(colorama.Fore.RED + '[-] This query seeks to identify the process acting as a parent or child process' + colorama.Style.RESET_ALL)
            print(arrow, f'{scnx_sourceprocessname} ({', '.join(new1)}) {colorama.Fore.BLUE}OR{colorama.Style.RESET_ALL} {scnx_destination_process_name} ({', '.join(new1)})')
            print(arrow, f'{scnx_sourceprocessname} ({', '.join(new2)}) {colorama.Fore.BLUE}OR{colorama.Style.RESET_ALL} {scnx_destination_process_name} ({', '.join(new2)})\n')
            print(colorama.Fore.RED + '[-] This query seeks to identify the parent processes and list them organized by the parent processes and command line' + colorama.Style.RESET_ALL)
            print(arrow, f'{scnx_sourceprocessname} ({', '.join(new1)}) {stats} {scnx_source_process_name_only} {command_line_only}')
            print(arrow, f'{scnx_sourceprocessname} ({', '.join(new2)}) {stats} {scnx_source_process_name_only} {command_line_only}\n')
            print(colorama.Fore.RED + '[-] This query seeks to identify child processes and list them organized by child processes and command line' + colorama.Style.RESET_ALL)
            print(arrow, f'{scnx_destination_process_name} ({', '.join(new1)}) {stats} {scnx_destination_process_name_only} {command_line_only}')
            print(arrow, f'{scnx_destination_process_name} ({', '.join(new2)}) {stats} {scnx_destination_process_name_only} {command_line_only}\n')
            print(colorama.Fore.GREEN + '[+] AV / EDR\n' + colorama.Style.RESET_ALL)
            print(colorama.Fore.RED + '[-] This query seeks to identify the processes identified by the antivirus or EDR solution' + colorama.Style.RESET_ALL)
            print(arrow, f'{scnx_filename} ({', '.join(new1)})')
            print(arrow, f'{scnx_filename} ({', '.join(new2)})\n')
            print(colorama.Fore.RED + '[-] This query seeks to identify the processes identified by the antivirus or EDR solution and list them organized by process' + colorama.Style.RESET_ALL)
            print(arrow, f'{scnx_filename} ({', '.join(new1)}) {stats} {scnx_file_name_only}')
            print(arrow, f'{scnx_filename} ({', '.join(new2)}) {stats} {scnx_file_name_only}\n')
            print(colorama.Fore.RED + '[-] This query seeks to identify the processes identified by the antivirus or EDR solution and list them organized by process and command line' + colorama.Style.RESET_ALL)
            print(arrow, f'{scnx_filename} ({', '.join(new1)}) {stats} {scnx_file_name_only} {childprocesscommandline_only}')
            print(arrow, f'{scnx_filename} ({', '.join(new2)}) {stats} {scnx_file_name_only} {childprocesscommandline_only}\n')           

            break

        if len(found_artifact) < 2:                    
            print(colorama.Fore.RED + 'The -l or --l argument only accepts values ​​equal to or greater than 2, possibly the source does not have more than one value or cannot be extracted correctly\n' + colorama.Style.RESET_ALL)


def artifact_scnx(arguments):
    
    if not artifact(arguments.input):
        print(colorama.Fore.RED + '[!] Not found artifact' + colorama.Style.RESET_ALL)
    else:        
        records_artifact = []  
        scnx_sourceprocessname = siem.scnx_source_process_name()
        scnx_source_process_name_only = siem.scnx_source_process_name_only()
        scnx_destination_process_name = siem.scnx_destination_process_name()
        scnx_destination_process_name_only = siem.scnx_destination_process_name_only()
        scnx_filename = siem.scnx_file_name()
        scnx_file_name_only = siem.scnx_file_name_only()
        found_artifact = artifact(arguments.input)
        command_line_only = siem.scnx_command_line_only()
        scnx_childprocesscommandline_only = siem.scnx_childprocesscommandline_only()
        scnx_baseeventid = siem.scnx_baseeventid()
        scnx_object_file = siem.scnx_object_file()
        scnx_object_file_only = siem.scnx_object_file_only()
        scnx_scriptpath_only = siem.scnx_scriptpath_only()
        scnx_filepath_only = siem.scnx_file_path_only()
        scnx_orginal_file_name = siem.scnx_original_file_name()
        scnx_orginal_file_name_only = siem.scnx_original_file_name_only()
        stats = siem.scnx_stats()

        arrow = colorama.Fore.RED + '    ↳  ' + colorama.Style.RESET_ALL

        if arguments.dll:
            found_artifact = [a for a in found_artifact if a.lower().endswith('.dll')]
            if not found_artifact:
                print(colorama.Fore.RED + '[!] Not found dll artifact' + colorama.Style.RESET_ALL)
                return

        if arguments.ps1:
            found_artifact = [a for a in found_artifact if a.lower().endswith('.ps1')] 
            if not found_artifact:
                print(colorama.Fore.RED + '[!] Not found ps1 artifact' + colorama.Style.RESET_ALL)
                return    

        if arguments.exe:
            found_artifact = [a for a in found_artifact if a.lower().endswith('.exe')]
            if not found_artifact:
                print(colorama.Fore.RED + '[!] Not found exe artifact' + colorama.Style.RESET_ALL)
                return       

        for index in found_artifact:
            records_artifact.append(index)

        if arguments.include:
            records_artifact.extend(arguments.include)
            records_artifact = list(set(records_artifact))

        if arguments.remove:
            records_artifact = [item for item in records_artifact if item not in arguments.remove]

        if arguments.dll:
            print(colorama.Fore.GREEN + '[+] Windows\n' + colorama.Style.RESET_ALL)
            print(colorama.Fore.RED + '[-] Event ID 4663 - An attempt was made to access an object \n' + colorama.Style.RESET_ALL)
            print(arrow, f'{scnx_baseeventid} (4663) {colorama.Fore.BLUE + 'and' + colorama.Style.RESET_ALL} {scnx_object_file} ({", ".join(records_artifact)})')
            print(arrow, f'{scnx_baseeventid} (4663) {colorama.Fore.BLUE + 'and' + colorama.Style.RESET_ALL} {scnx_object_file} ({", ".join(records_artifact)} {stats} {scnx_object_file_only}\n')

        if arguments.ps1:
            print(colorama.Fore.GREEN + '[+] Windows - Powershell\n' + colorama.Style.RESET_ALL)
            script_path_without = f' {colorama.Fore.BLUE + 'OR' + colorama.Style.RESET_ALL} {scnx_scriptpath_only} {colorama.Fore.BLUE + 'contains ' + colorama.Style.RESET_ALL}'
            print(colorama.Fore.RED + '[-] Event ID 4104 - Script Block Logging \n' + colorama.Style.RESET_ALL)
            print(arrow, f'{scnx_baseeventid} (4104) {colorama.Fore.BLUE + 'and' + colorama.Style.RESET_ALL} {scnx_scriptpath_only} {colorama.Fore.BLUE + 'contains' + colorama.Style.RESET_ALL}  {script_path_without.join(records_artifact)}')
            print(arrow, f'{scnx_baseeventid} (4104) {colorama.Fore.BLUE + 'and' + colorama.Style.RESET_ALL} {scnx_scriptpath_only} {colorama.Fore.BLUE + 'contains' + colorama.Style.RESET_ALL}  {script_path_without.join(records_artifact)} {stats} {scnx_scriptpath_only}\n')            
            print(colorama.Fore.GREEN + '[+] Windows - Sysmon\n' + colorama.Style.RESET_ALL)
            print(colorama.Fore.RED + '[-] Event ID 1 - Process Creation \n' + colorama.Style.RESET_ALL)
            childprocesscommandline_without = f' {colorama.Fore.BLUE + 'OR' + colorama.Style.RESET_ALL} {scnx_childprocesscommandline_only} {colorama.Fore.BLUE + 'contains ' + colorama.Style.RESET_ALL}'
            print(arrow, f'{scnx_baseeventid} (1) {colorama.Fore.BLUE + 'and' + colorama.Style.RESET_ALL} {scnx_childprocesscommandline_only} {colorama.Fore.BLUE + 'contains' + colorama.Style.RESET_ALL}  {childprocesscommandline_without.join(records_artifact)}')
            print(arrow, f'{scnx_baseeventid} (1) {colorama.Fore.BLUE + 'and' + colorama.Style.RESET_ALL} {scnx_childprocesscommandline_only} {colorama.Fore.BLUE + 'contains' + colorama.Style.RESET_ALL}  {childprocesscommandline_without.join(records_artifact)} {stats} {scnx_childprocesscommandline_only}\n')
           
           
        if arguments.exe:
            print(colorama.Fore.GREEN + '[+] Windows - Sysmon\n' + colorama.Style.RESET_ALL)
            print(colorama.Fore.RED + '[-] Event ID 1 - Process Creation \n' + colorama.Style.RESET_ALL)
            childprocesscommandline_without = f' {colorama.Fore.BLUE + 'OR' + colorama.Style.RESET_ALL} {scnx_childprocesscommandline_only} {colorama.Fore.BLUE + 'contains ' + colorama.Style.RESET_ALL}'
            print(arrow, f'{scnx_baseeventid} (1) {colorama.Fore.BLUE + 'and' + colorama.Style.RESET_ALL} {scnx_childprocesscommandline_only} {colorama.Fore.BLUE + 'contains' + colorama.Style.RESET_ALL}  {childprocesscommandline_without.join(records_artifact)}')
            print(arrow, f'{scnx_baseeventid} (1) {colorama.Fore.BLUE + 'and' + colorama.Style.RESET_ALL} {scnx_childprocesscommandline_only} {colorama.Fore.BLUE + 'contains' + colorama.Style.RESET_ALL}  {childprocesscommandline_without.join(records_artifact)} {stats} {scnx_childprocesscommandline_only}\n')
            
        
        if not arguments.dll and not arguments.ps1 and not arguments.exe:
            print(colorama.Fore.GREEN + '[+] Windows / Linux\n' + colorama.Style.RESET_ALL)
            print(colorama.Fore.RED + '[-] This query seeks to identify the process acting as the parent process' + colorama.Style.RESET_ALL)
            print(arrow, f'{scnx_sourceprocessname} ({", ".join(records_artifact)})\n')
            print(colorama.Fore.RED + '[-] This query seeks to identify the process acting as a child process' + colorama.Style.RESET_ALL)
            print(arrow, f'{scnx_destination_process_name} ({", ".join(records_artifact)})\n')
            print(colorama.Fore.RED + '[-] This query seeks to identify the process acting as a parent or child process' + colorama.Style.RESET_ALL)
            print(arrow, f'{scnx_sourceprocessname} ({", ".join(records_artifact)}) {colorama.Fore.BLUE}OR{colorama.Style.RESET_ALL} {scnx_destination_process_name} ({", ".join(records_artifact)})\n')
            print(colorama.Fore.RED + '[-] This query seeks to identify the parent processes and list them organized by the parent processes and command line' + colorama.Style.RESET_ALL)
            print(arrow, f'{scnx_sourceprocessname} ({", ".join(records_artifact)}) {stats} {scnx_source_process_name_only} {command_line_only}\n')
            print(colorama.Fore.RED + '[-] This query seeks to identify child processes and list them organized by child processes and command line' + colorama.Style.RESET_ALL)
            print(arrow, f'{scnx_destination_process_name} ({", ".join(records_artifact)}) {stats} {scnx_destination_process_name_only} {command_line_only}\n')
            print(colorama.Fore.RED + '[-] This query seeks to identify the parent processes and lists them organized by the parent, child process and command line' + colorama.Style.RESET_ALL)
            print(arrow, f'{scnx_sourceprocessname} ({", ".join(records_artifact)}) {stats} {scnx_source_process_name_only} {scnx_destination_process_name_only} {command_line_only}\n')
            print(colorama.Fore.RED + '[-] This query seeks to identify the parent or child processes and lists them organized by the parent, child processes and command line' + colorama.Style.RESET_ALL)
            print(arrow, f'{scnx_sourceprocessname} ({", ".join(records_artifact)}) {colorama.Fore.BLUE}OR{colorama.Style.RESET_ALL} {scnx_destination_process_name} ({", ".join(records_artifact)}) {stats} {scnx_source_process_name_only} {scnx_destination_process_name_only} {command_line_only}\n')
            print(colorama.Fore.GREEN + '[+] AV / EDR\n' + colorama.Style.RESET_ALL)
            print(colorama.Fore.RED + '[-] This query seeks to identify the processes identified by the antivirus or EDR solution' + colorama.Style.RESET_ALL)
            print(arrow, f'{scnx_filename} ({", ".join(records_artifact)})\n')
            print(colorama.Fore.RED + '[-] This query seeks to identify the processes identified by the antivirus or EDR solution and list them organized by process' + colorama.Style.RESET_ALL)
            print(arrow, f'{scnx_filename} ({", ".join(records_artifact)}) {stats} {scnx_file_name_only}\n')
            print(colorama.Fore.RED + '[-] This query seeks to identify the processes identified by the antivirus or EDR solution and list them organized by process and command line' + colorama.Style.RESET_ALL)
            print(arrow, f'{scnx_filename} ({", ".join(records_artifact)}) {stats} {scnx_file_name_only} {scnx_childprocesscommandline_only}\n')
            print(colorama.Fore.RED + '[-] This query seeks to identify the processes identified by the antivirus or EDR solution and list them organized by process, command line and process path' + colorama.Style.RESET_ALL)
            print(arrow, f'{scnx_filename} ({", ".join(records_artifact)}) {stats} {scnx_file_name_only} {scnx_childprocesscommandline_only} {scnx_filepath_only} \n')
            

def artifact_rsa_l(arguments):
    
    if not artifact(arguments.input):
        print(colorama.Fore.RED + '[!] Not found artifact' + colorama.Style.RESET_ALL)
    else:        

        records_artifact = []
        rsa_process = siem.process_contains()
        found_artifact = artifact(args.input)

        for index in found_artifact:
            records_artifact.append("'" + index + "'")
            meadle = len(records_artifact) // 2
            new1 = records_artifact[:meadle]
            new2 = records_artifact[meadle:]


        print(colorama.Fore.GREEN + '[+] AV / EDR / Windows / Linux\n' + colorama.Style.RESET_ALL)
        color = ' ||' + colorama.Fore.BLUE + ' process contains ' + colorama.Style.RESET_ALL
        print(f'{rsa_process} {color.join(new1)}\n')
        color = ' ||' + colorama.Fore.BLUE + ' process contains ' + colorama.Style.RESET_ALL
        print(f'{rsa_process} {color.join(new2)}')


def artifact_rsa(arguments):
    
    if not artifact(arguments.input):
        print(colorama.Fore.RED + '[!] Not found artifact' + colorama.Style.RESET_ALL)
    else:
        records_artifact = []
        rsa_process = siem.process_contains()
        found_artifact = artifact(args.input)

        for index in found_artifact:
            records_artifact.append("'" + index + "'")

        print(colorama.Fore.GREEN + '[+] AV / EDR / Windows / Linux\n' + colorama.Style.RESET_ALL)
        color = ' ||' + colorama.Fore.BLUE + ' process contains ' + colorama.Style.RESET_ALL
        print(f'{rsa_process} {color.join(records_artifact)}')


def artifact_only(arguments):
        
    if not artifact(arguments.input):
        print(colorama.Fore.RED + '[!] Not found artifact' + colorama.Style.RESET_ALL)
    else:
        print(colorama.Fore.GREEN + '[+] Artifacts\n' + colorama.Style.RESET_ALL)
        found_artifact = artifact(args.input)
        for index in set(found_artifact):
            print(index)


def md5_scnx_l(arguments):
    
    if not md5(arguments.input):
        print(colorama.Fore.RED + '[!] Not found md5 hashes' + colorama.Style.RESET_ALL)
    else:        
        records_md5 = []
        scnx_old_file_hash = siem.scnx_old_file_hash()
        scnx_old_file_hash_only = siem.scnx_old_file_hash_only()
        scnx_file_hash = siem.scnx_file_hash()
        scnx_file_hash_only = siem.scnx_file_hash_only()
        found_md5 = md5(args.input)
        stats = siem.scnx_stats()

        while len(found_md5) >= 2:

            for index in found_md5:
                records_md5.append(index)
                meadle = len(records_md5) // 2
                new1 = records_md5[:meadle]
                new2 = records_md5[meadle:]

            arrow = colorama.Fore.RED + '    ↳  ' + colorama.Style.RESET_ALL
            print(colorama.Fore.GREEN + '[+] AV / EDR / NGFW\n' + colorama.Style.RESET_ALL)
            print(colorama.Fore.RED + '[-] This query seeks to identify MD5 hash values\n' + colorama.Style.RESET_ALL)
            print(arrow, f'{scnx_old_file_hash} ({', '.join(new1)})')
            print(arrow, f'{scnx_old_file_hash} ({', '.join(new2)})')
            print(arrow, f'{scnx_file_hash} ({', '.join(new1)})')
            print(arrow, f'{scnx_file_hash} ({', '.join(new2)})\n')
            print(colorama.Fore.RED + '[-] This query seeks to identify MD5 hash values ​​ordered by MD5 hash values\n' + colorama.Style.RESET_ALL)
            print(arrow, f'{scnx_old_file_hash} ({', '.join(new1)}) {stats} {scnx_old_file_hash_only}')
            print(arrow, f'{scnx_old_file_hash} ({', '.join(new2)}) {stats} {scnx_old_file_hash_only}')
            print(arrow, f'{scnx_file_hash} ({', '.join(new1)}) {stats} {scnx_file_hash_only}')
            print(arrow, f'{scnx_file_hash} ({', '.join(new2)}) {stats} {scnx_file_hash_only}\n')

            break

        if len(found_md5) < 2:                    
            print(colorama.Fore.RED + 'The -l or --l argument only accepts values ​​equal to or greater than 2, possibly the source does not have more than one value or cannot be extracted correctly\n' + colorama.Style.RESET_ALL)


def md5_scnx(arguments):
    
    if not md5(arguments.input):
        print(colorama.Fore.RED + '[!] Not found md5 hashes' + colorama.Style.RESET_ALL)
    else:        
        records_md5 = []
        scnx_old_file_hash = siem.scnx_old_file_hash()
        scnx_old_file_hash_only = siem.scnx_old_file_hash_only()
        scnx_file_hash = siem.scnx_file_hash()
        scnx_file_hash_only = siem.scnx_file_hash_only()            
        found_md5 = md5(args.input)
        stats = siem.scnx_stats()

        for index in found_md5:
            records_md5.append(index)

        arrow = colorama.Fore.RED + '    ↳  ' + colorama.Style.RESET_ALL        
        print(colorama.Fore.GREEN + '[+] AV / EDR \n' + colorama.Style.RESET_ALL)
        print(colorama.Fore.RED + '[-] This query seeks to identify MD5 hash values\n' + colorama.Style.RESET_ALL)
        print(arrow, f'{scnx_old_file_hash} ({', '.join(records_md5)})')        
        print(arrow, f'{scnx_file_hash} ({', '.join(records_md5)})\n')
        print(colorama.Fore.RED + '[-] This query seeks to identify MD5 hash values ​​ordered by MD5 hash values\n' + colorama.Style.RESET_ALL)
        print(arrow, f'{scnx_old_file_hash} ({', '.join(records_md5)}) {stats} {scnx_old_file_hash_only}')
        print(arrow, f'{scnx_file_hash} ({', '.join(records_md5)}) {stats} {scnx_file_hash_only}\n')


def md5_rsa_l(arguments):
    
    if not md5(arguments.input):
        print(colorama.Fore.RED + '[!] Not found md5 hashes' + colorama.Style.RESET_ALL)
    else:        
        records_md5 = []
        rsa_checksum = siem.rsa_cheksum()
        found_checksum = md5(args.input)

        while len(found_checksum) >= 2:

            for index in found_checksum:
                records_md5.append(index)
                meadle = len(records_md5) // 2
                new1 = records_md5[:meadle]
                new2 = records_md5[meadle:]

            print(colorama.Fore.GREEN + '[+] AV / EDR\n' + colorama.Style.RESET_ALL)

            color = ' ||' + colorama.Fore.BLUE + ' checksum = ' + colorama.Style.RESET_ALL + "'"
            records_md5_two = [f"{sha256}'" for sha256 in new1]
            print(f'{rsa_checksum} {color.join(records_md5_two)} \n')
            color = ' ||' + colorama.Fore.BLUE + ' checksum = ' + colorama.Style.RESET_ALL + "'"
            records_md5_two = [f"{sha256}'" for sha256 in new2]
            print(f'{rsa_checksum} {color.join(records_md5_two)} \n') 

            print(colorama.Fore.GREEN + '[SYSMON]\n' + colorama.Style.RESET_ALL)

            color = ' ||' + colorama.Fore.BLUE + ' checksum = ' + colorama.Style.RESET_ALL + "'md5="
            records_md5_two = [f"{md5}'" for md5 in new1]        
            print(f"{rsa_checksum} 'md5={color.join(records_md5_two)}\n")
            color = ' ||' + colorama.Fore.BLUE + ' checksum = ' + colorama.Style.RESET_ALL + "'md5="
            records_md5_two = [f"{md5}'" for md5 in new2]        
            print(f"{rsa_checksum} 'md5={color.join(records_md5_two)}")

            break

        if len(found_checksum) < 2:                    
            print(colorama.Fore.RED + 'The -l or --l argument only accepts values ​​equal to or greater than 2, possibly the source does not have more than one value or cannot be extracted correctly\n' + colorama.Style.RESET_ALL)


def md5_rsa(arguments):
    
    if not md5(arguments.input):
        print(colorama.Fore.RED + '[!] Not found md5 hashes' + colorama.Style.RESET_ALL)
    else:        
        records_md5 = []
        rsa_checksum = siem.rsa_cheksum()
        found_checksum = md5(args.input)

        for index in found_checksum:
            records_md5.append(index)

        print(colorama.Fore.GREEN + '[+] AV / EDR\n' + colorama.Style.RESET_ALL)
        color = ' ||' + colorama.Fore.BLUE + ' checksum = ' + colorama.Style.RESET_ALL + "'"
        records_md5_two = [f"{md5}'" for md5 in records_md5]
        print(f'{rsa_checksum} \'{color.join(records_md5_two)} \n') 
        print(colorama.Fore.GREEN + '[+] SYSMON\n')

        color = ' ||' + colorama.Fore.BLUE + ' checksum = ' + colorama.Style.RESET_ALL + "'md5="
        records_md5 = [f"{md5}'" for md5 in records_md5]        
        print(f"{rsa_checksum} 'md5={color.join(records_md5)}")        


def md5_only(arguments):

    if not md5(arguments.input):
        print(colorama.Fore.RED + '[!] Not found md5 hashes' + colorama.Style.RESET_ALL)
    else:
        print(colorama.Fore.GREEN + '[+] Hashes md5\n' + colorama.Style.RESET_ALL)
        found_md5 = md5(args.input)
        for index in set(found_md5):
            print(index)
    

def sha1_scnx_l(arguments):  
          
    if not sha1(arguments.input):
        print(colorama.Fore.RED + '[!] Not found sha1 hashes' + colorama.Style.RESET_ALL)
    else:        
        records_sha1 = []
        scnx_old_file_hash = siem.scnx_old_file_hash()
        scnx_old_file_hash_only = siem.scnx_old_file_hash_only()
        scnx_file_hash = siem.scnx_file_hash()
        scnx_file_hash_only = siem.scnx_file_hash_only()
        found_sha1 = sha1(args.input)
        scnx_md5hash = siem.scnx_md5hash()
        stats = siem.scnx_stats()

        while len(found_sha1) >= 2:
        
            for index in found_sha1:
                records_sha1.append(index)
                meadle = len(records_sha1) // 2
                new1 = records_sha1[:meadle]
                new2 = records_sha1[meadle:]

            arrow = colorama.Fore.RED + '    ↳  ' + colorama.Style.RESET_ALL
            print(colorama.Fore.GREEN + '[+] AV / EDR\n' + colorama.Style.RESET_ALL)
            print(colorama.Fore.RED + '[-] This query seeks to identify SHA1 hash values\n' + colorama.Style.RESET_ALL)
            print(arrow, f'{scnx_old_file_hash} ({', '.join(new1)})')
            print(arrow, f'{scnx_old_file_hash} ({', '.join(new2)})')
            print(arrow, f'{scnx_file_hash} ({', '.join(new1)})')
            print(arrow, f'{scnx_file_hash} ({', '.join(new2)})\n')
            print(colorama.Fore.RED + '[-] This query seeks to identify SHA1 hash values ​​ordered by SHA1 hash values\n' + colorama.Style.RESET_ALL)
            print(arrow, f'{scnx_old_file_hash} ({', '.join(new1)}) {stats} {scnx_old_file_hash_only}')
            print(arrow, f'{scnx_old_file_hash} ({', '.join(new2)}) {stats} {scnx_old_file_hash_only}')
            print(arrow, f'{scnx_file_hash} ({', '.join(new1)}) {stats} {scnx_file_hash_only}')
            print(arrow, f'{scnx_file_hash} ({', '.join(new2)}) {stats} {scnx_file_hash_only}\n')
            print(colorama.Fore.GREEN + '[+] Windows - Sysmon\n' + colorama.Style.RESET_ALL)
            print(colorama.Fore.RED + '[-] This query seeks to identify SHA1 hash values ​​ordered by SHA1 hash values in channel sysmon\n' + colorama.Style.RESET_ALL)
            print(arrow, f'{scnx_md5hash} ({', '.join(new1)})')
            print(arrow, f'{scnx_md5hash} ({', '.join(new2)})')
            print(arrow, f'{scnx_md5hash} ({', '.join(new1)}) {stats} {scnx_md5hash}')
            print(arrow, f'{scnx_md5hash} ({', '.join(new2)}) {stats} {scnx_md5hash}\n')

            break

        if len(found_sha1) < 2:                    
            print(colorama.Fore.RED + 'The -l or --l argument only accepts values ​​equal to or greater than 2, possibly the source does not have more than one value or cannot be extracted correctly\n' + colorama.Style.RESET_ALL)


def sha1_scnx(arguments):   

    if not sha1(arguments.input):
        print(colorama.Fore.RED + '[!] Not found sha1 hashes' + colorama.Style.RESET_ALL)
    else:        
        records_sha1 = []
        scnx_old_file_hash = siem.scnx_old_file_hash()
        scnx_old_file_hash_only = siem.scnx_old_file_hash_only()
        scnx_file_hash = siem.scnx_file_hash()
        scnx_file_hash_only = siem.scnx_file_hash_only()
        found_sha1 = sha1(args.input)
        scnx_md5hash = siem.scnx_md5hash()
        stats = siem.scnx_stats()

        for index in found_sha1:
            records_sha1.append(index)

        arrow = colorama.Fore.RED + '    ↳  ' + colorama.Style.RESET_ALL
        print(colorama.Fore.GREEN + '[+] AV / EDR\n' + colorama.Style.RESET_ALL)
        print(colorama.Fore.RED + '[-] This query seeks to identify SHA1 hash values\n' + colorama.Style.RESET_ALL)
        print(arrow, f'{scnx_old_file_hash} ({', '.join(records_sha1)})')
        print(arrow, f'{scnx_file_hash} ({', '.join(records_sha1)})\n')
        print(colorama.Fore.RED + '[-] This query seeks to identify SHA1 hash values ​​ordered by SHA1 hash values\n' + colorama.Style.RESET_ALL)
        print(arrow, f'{scnx_old_file_hash} ({', '.join(records_sha1)}) {stats} {scnx_old_file_hash_only}')
        print(arrow, f'{scnx_file_hash} ({', '.join(records_sha1)}) {stats} {scnx_file_hash_only}\n')
        print(colorama.Fore.GREEN + '[+] Windows - Sysmon\n' + colorama.Style.RESET_ALL)
        print(colorama.Fore.RED + '[-] This query seeks to identify SHA1 hash values in channel sysmon\n' + colorama.Style.RESET_ALL)
        print(arrow, f'{scnx_md5hash} ({', '.join(records_sha1)})\n')
        print(colorama.Fore.RED + '[-] This query seeks to identify SHA1 hash values ​​ordered by SHA1 hash values in channel sysmon\n' + colorama.Style.RESET_ALL)
        print(arrow, f'{scnx_md5hash} ({', '.join(records_sha1)}) {stats} {scnx_md5hash}\n')


def sha1_rsa_l(arguments):

    if not sha1(arguments.input):
        print(colorama.Fore.RED + '[!] Not found sha1 hashes' + colorama.Style.RESET_ALL)
    else:        
        records_sha1 = []
        rsa_checksum = siem.rsa_cheksum()
        found_checksum = sha1(args.input)

        while len(found_checksum) >= 2:

            for index in found_checksum:
                records_sha1.append(index)
                meadle = len(records_sha1) // 2
                new1 = records_sha1[:meadle]
                new2 = records_sha1[meadle:]

            print(colorama.Fore.GREEN + '[+] AV / EDR\n' + colorama.Style.RESET_ALL)
            
            color = ' || ' + colorama.Fore.BLUE + ' checksum = ' + colorama.Style.RESET_ALL + "'"
            records_sha1_two = [f"{sha1}'" for sha1 in new1]
            print(f'{rsa_checksum} {color.join(records_sha1_two)}\n')  

            color = ' || ' + colorama.Fore.BLUE + ' checksum = ' + colorama.Style.RESET_ALL + "'"
            records_sha1_two = [f"{sha1}'" for sha1 in new2]
            print(f'{rsa_checksum} {color.join(records_sha1_two)}\n')

            print('colorama.Fore.GREEN + [+] SYSMON\n')

            color = ' ||' + colorama.Fore.BLUE + ' checksum = ' + colorama.Style.RESET_ALL + "'sha1="
            records_sha1_two = [f"{sha1}'" for sha1 in new1]
            print(f"{rsa_checksum} 'sha1={color.join(records_sha1_two)}\n")

            color = ' ||' + colorama.Fore.BLUE + ' checksum = ' + colorama.Style.RESET_ALL + "'sha1="
            records_sha1_two = [f"{sha1}'" for sha1 in new2]
            print(f"{rsa_checksum} 'sha1={color.join(records_sha1_two)}")

            break

        if len(found_checksum) < 2:                    
            print(colorama.Fore.RED + 'The -l or --l argument only accepts values ​​equal to or greater than 2, possibly the source does not have more than one value or cannot be extracted correctly\n' + colorama.Style.RESET_ALL)


def sha1_rsa(arguments):
    
    if not sha1(arguments.input):
        print(colorama.Fore.RED + '[!] Not found sha1 hashes' + colorama.Style.RESET_ALL)
    else:        
        records_sha1 = []
        rsa_checksum = siem.rsa_cheksum()
        found_checksum = sha1(args.input)

        for index in found_checksum:
            records_sha1.append(index)

        print(colorama.Fore.GREEN + '[+] AV / EDR\n' + colorama.Style.RESET_ALL)
        
        color = ' || ' + colorama.Fore.BLUE + ' checksum = ' + colorama.Style.RESET_ALL + "'"
        records_sha1_two = [f"{sha1}'" for sha1 in records_sha1]
        print(f'{rsa_checksum} \'{color.join(records_sha1_two)}\n')  

        print(colorama.Fore.GREEN + '[+] SYSMON\n')

        color = ' ||' + colorama.Fore.BLUE + ' checksum = ' + colorama.Style.RESET_ALL + "'sha1="
        records_sha1 = [f"{sha1}'" for sha1 in records_sha1]
        print(f"{rsa_checksum} 'sha1={color.join(records_sha1)}") 


def sha1_only(arguments):

    if not sha1(arguments.input):
        print(colorama.Fore.RED + '[!] Not found sha1 hashes' + colorama.Style.RESET_ALL)
    else: 
        print(colorama.Fore.GREEN + '[+] Hashes sha1\n' + colorama.Style.RESET_ALL)       
        found_sha1 = sha1(args.input)
        for index in set(found_sha1):
            print(index)


def sha256_scnx_l(arguments):

    if not sha256(arguments.input):
        print(colorama.Fore.RED + '[!] Not found sha256 hashes' + colorama.Style.RESET_ALL)
    else:
        records_sha256 = []
        scnx_old_file_hash = siem.scnx_old_file_hash()
        scnx_old_file_hash_only = siem.scnx_old_file_hash_only()
        scnx_file_hash = siem.scnx_file_hash()
        scnx_file_hash_only = siem.scnx_file_hash_only()
        found_sha256 = sha256(arguments.input)
        stats = siem.scnx_stats()

        while len(found_sha256) >= 2:

            for index in set(found_sha256):
                records_sha256.append(index)
                meadle = len(records_sha256) // 2
                new1 = records_sha256[:meadle]
                new2 = records_sha256[meadle:]

            arrow = colorama.Fore.RED + '    ↳  ' + colorama.Style.RESET_ALL
            print(colorama.Fore.GREEN + '[+] AV / EDR\n' + colorama.Style.RESET_ALL)
            print(colorama.Fore.RED + '[-] This query seeks to identify SHA256 hash values\n' + colorama.Style.RESET_ALL)
            print(arrow, f'{scnx_old_file_hash} ({', '.join(new1)})')   
            print(arrow, f'{scnx_old_file_hash} ({', '.join(new2)})')
            print(arrow, f'{scnx_file_hash} ({', '.join(new1)})')   
            print(arrow, f'{scnx_file_hash} ({', '.join(new2)})\n')
            print(colorama.Fore.RED + '[-] This query seeks to identify SHA1 hash values ​​ordered by SHA256 hash values\n' + colorama.Style.RESET_ALL)
            print(arrow, f'{scnx_old_file_hash} ({', '.join(new1)}) {stats} {scnx_old_file_hash_only}')
            print(arrow, f'{scnx_old_file_hash} ({', '.join(new2)}) {stats} {scnx_old_file_hash_only}')
            print(arrow, f'{scnx_file_hash} ({', '.join(new1)}) {stats} {scnx_file_hash_only}')
            print(arrow, f'{scnx_file_hash} ({', '.join(new2)}) {stats} {scnx_file_hash_only}\n')

            break

        if len(found_sha256) < 2:                    
            print(colorama.Fore.RED + 'The -l or --l argument only accepts values ​​equal to or greater than 2, possibly the source does not have more than one value or cannot be extracted correctly\n' + colorama.Style.RESET_ALL)


def sha256_scnx(arguments):

    if not sha256(arguments.input):
        print(colorama.Fore.RED + '[!] Not found sha256 hashes' + colorama.Style.RESET_ALL)
    else:
        records_sha256 = []
        scnx_old_file_hash = siem.scnx_old_file_hash()
        scnx_old_file_hash_only = siem.scnx_old_file_hash_only()
        scnx_file_hash = siem.scnx_file_hash()
        found_sha256 = sha256(arguments.input)
        stats = siem.scnx_stats()

        for index in set(found_sha256):
            records_sha256.append(index)

        arrow = colorama.Fore.RED + '    ↳  ' + colorama.Style.RESET_ALL
        print(colorama.Fore.GREEN + '[+] AV / EDR\n' + colorama.Style.RESET_ALL)
        print(colorama.Fore.RED + '[-] This query seeks to identify SHA256 hash values\n' + colorama.Style.RESET_ALL)
        print(arrow, f'{scnx_file_hash} ({', '.join(records_sha256)})')
        print(arrow, f'{scnx_old_file_hash} ({', '.join(records_sha256)})\n')
        print(colorama.Fore.RED + '[-] This query seeks to identify SHA1 hash values ​​ordered by SHA256 hash values\n' + colorama.Style.RESET_ALL)  
        print(arrow, f'{scnx_file_hash} ({', '.join(records_sha256)}) {stats} {scnx_old_file_hash_only}') 
        print(arrow, f'{scnx_old_file_hash} ({', '.join(records_sha256)}) {stats} {scnx_old_file_hash_only}\n') 


def sha256_rsa_l(arguments):

    if not sha256(arguments.input):
        print(colorama.Fore.RED + '[!] Not found sha256 hashes' + colorama.Style.RESET_ALL)
    else:
        records_sha256 = []
        rsa_checksum = siem.rsa_cheksum()
        found_checksum = sha256(args.input)

        while len(found_checksum) >= 2:

            for index in found_checksum:
                records_sha256.append(index)
                meadle = len(records_sha256) // 2
                new1 = records_sha256[:meadle]
                new2 = records_sha256[meadle:]

            print(colorama.Fore.GREEN + '[+] AV / EDR\n' + colorama.Style.RESET_ALL)

            color = ' || ' + colorama.Fore.BLUE + ' checksum = ' + colorama.Style.RESET_ALL + "'"
            records_sha256_two = [f"{sha256}'" for sha256 in new1]
            print(f'{rsa_checksum} {color.join(records_sha256_two)}\n')
            color = ' || ' + colorama.Fore.BLUE + ' checksum = ' + colorama.Style.RESET_ALL+ "'"
            records_sha256_two = [f"{sha256}'" for sha256 in new2]
            print(f'{rsa_checksum} {color.join(records_sha256_two)}\n')
            print('[+] SYSMON\n')
            color = ' ||' + colorama.Fore.BLUE + ' checksum = ' + colorama.Style.RESET_ALL + "'sha256="
            records_sha256_two = [f"{sha256}'" for sha256 in new1]
            print(f"{rsa_checksum} 'sha256={color.join(records_sha256_two)}\n")
            color = ' ||' + colorama.Fore.BLUE + ' checksum = ' + colorama.Style.RESET_ALL + "'sha256="
            records_sha256_two = [f"{sha256}'" for sha256 in new2]
            print(f"{rsa_checksum} 'sha256={color.join(records_sha256_two)}") 

            break

        if len(found_checksum) < 2:                    
            print(colorama.Fore.RED + 'The -l or --l argument only accepts values ​​equal to or greater than 2, possibly the source does not have more than one value or cannot be extracted correctly\n' + colorama.Style.RESET_ALL)


def sha256_rsa(arguments):

        if not sha256(arguments.input):
            print(colorama.Fore.RED + '[!] Not found sha256 hashes' + colorama.Style.RESET_ALL)
        else:
            records_sha256 = []
            rsa_checksum = siem.rsa_cheksum()
            found_checksum = sha256(args.input)

            for index in found_checksum:
                records_sha256.append(index)
                

            print(colorama.Fore.GREEN + '[+] AV / EDR\n' + colorama.Style.RESET_ALL)

            color = ' || ' + colorama.Fore.BLUE + ' checksum = ' + colorama.Style.RESET_ALL + "'"
            records_sha256_two = [f"{sha256}'" for sha256 in records_sha256]
            print(f'{rsa_checksum} \'{color.join(records_sha256_two)}\n')
            print(colorama.Fore.GREEN + '[SYSMON]\n' + colorama.Style.RESET_ALL)
            color = ' ||' + colorama.Fore.BLUE + ' checksum = ' + colorama.Style.RESET_ALL + "'sha256="
            records_sha256 = [f"{sha256}'" for sha256 in records_sha256]
            print(f"{rsa_checksum} 'sha256={color.join(records_sha256)}") 
        

def sha256_only(arguments):

        if not sha256(arguments.input):
            print(colorama.Fore.RED + '[!] Not found sha256 hashes' + colorama.Style.RESET_ALL)
        else:
            print(colorama.Fore.GREEN + '[+] hashes sha256\n' + colorama.Style.RESET_ALL)
            found_sha256 = sha256(args.input)
            for index in set(found_sha256):
                print(index)


def email_scnx_l(arguments):

        if not email(arguments.input):
            print(colorama.Fore.RED + '[!] Not found email address' + colorama.Style.RESET_ALL)
        else:
            records_email = []
            scnx_mailboxownerupn = siem.scnx_mailboxownerupn()
            scnx_mailboxownerupn_without = siem.scnx_mailboxownerupn_without()
            scnx_workemail = siem.scnx_workemail()
            scnx_workemail_without = siem.scnx_workemail_without() 
            scnx_accountname = siem.scnx_accountname()
            scnx_accountname_without = siem.scnx_accountname_without()
            scnx_email_recipient = siem.scnx_email_recipient()
            scnx_email_recipient_only = siem.scnx_email_recipient_domain_only()
            found_email = email(arguments.input)
            stats = siem.scnx_stats()

            while len(found_email) >= 2:

                for index in set(found_email):
                    records_email.append(index)

                    if args.include:
                        records_email.extend(args.include)
                        records_email = list(set(records_email))
                
                    if args.remove:
                        records_email = [item for item in records_email if item not in args.remove]

                    meadle = len(records_email) // 2
                    new1 = records_email[:meadle]
                    new2 = records_email[meadle:]

                arrow = colorama.Fore.RED + '    ↳  ' + colorama.Style.RESET_ALL
                print(colorama.Fore.GREEN + '[+] EXCHANGE\n' + colorama.Style.RESET_ALL)
                print(colorama.Fore.RED + '[-] This query seeks to identify email addresses\n' + colorama.Style.RESET_ALL)
                print(arrow, f'{scnx_mailboxownerupn} ({', '.join(new1)})')   
                print(arrow, f'{scnx_mailboxownerupn} ({', '.join(new2)})')
                print(arrow, f'{scnx_accountname} ({', '.join(new1)})')   
                print(arrow, f'{scnx_accountname} ({', '.join(new2)})')
                print(arrow, f'{scnx_workemail} ({', '.join(new1)})') 
                print(arrow, f'{scnx_workemail} ({', '.join(new2)})')
                print(arrow, f'{scnx_email_recipient} ({', '.join(new1)})') 
                print(arrow, f'{scnx_email_recipient} ({', '.join(new2)})\n')
                print(colorama.Fore.RED + '[-] This query seeks to identify queried values ​​organized by the values ​​of the queried metakey\n' + colorama.Style.RESET_ALL)
                print(arrow, f'{scnx_mailboxownerupn} ({', '.join(new1)}) {stats} {scnx_mailboxownerupn_without}')   
                print(arrow, f'{scnx_mailboxownerupn} ({', '.join(new2)}) {stats} {scnx_mailboxownerupn_without}')
                print(arrow, f'{scnx_accountname} ({', '.join(new1)}) {stats} {scnx_accountname_without}')   
                print(arrow, f'{scnx_accountname} ({', '.join(new2)}) {stats} {scnx_accountname_without}')
                print(arrow, f'{scnx_workemail} ({', '.join(new1)}) {stats} {scnx_workemail_without}')   
                print(arrow, f'{scnx_workemail} ({', '.join(new2)}) {stats} {scnx_workemail_without}')
                print(arrow, f'{scnx_email_recipient} ({', '.join(new1)}) {stats} {scnx_email_recipient_only}')   
                print(arrow, f'{scnx_email_recipient} ({', '.join(new2)}) {stats} {scnx_email_recipient_only}\n')

                break

            if len(found_email) < 2:                    
                print(colorama.Fore.RED + 'The -l or --l argument only accepts values ​​equal to or greater than 2, possibly the source does not have more than one value or cannot be extracted correctly\n' + colorama.Style.RESET_ALL)


def email_scnx(arguments):

        if not email(arguments.input):
            print(colorama.Fore.RED + '[!] Not found email address' + colorama.Style.RESET_ALL)
        else:
            records_email = []
            scnx_mailboxownerupn = siem.scnx_mailboxownerupn()
            scnx_mailboxownerupn_without = siem.scnx_mailboxownerupn_without()
            scnx_workemail = siem.scnx_workemail()
            scnx_workemail_without = siem.scnx_workemail_without() 
            scnx_accountname = siem.scnx_accountname()
            scnx_accountname_without = siem.scnx_accountname_without()
            scnx_email_recipient = siem.scnx_email_recipient()
            scnx_email_recipient_only = siem.scnx_email_recipient_domain_only()
            found_email = email(arguments.input)
            stats = siem.scnx_stats()

            for index in set(found_email):
                records_email.append(index)

                if args.include:
                        records_email.extend(args.include)
                        records_email = list(set(records_email))
                
                if args.remove:
                    records_email = [item for item in records_email if item not in args.remove]

            arrow = colorama.Fore.RED + '    ↳  ' + colorama.Style.RESET_ALL
            print(colorama.Fore.GREEN + '[+] EXCHANGE\n' + colorama.Style.RESET_ALL)
            print(colorama.Fore.RED + '[-] This query seeks to identify email addresses\n' + colorama.Style.RESET_ALL)
            print(arrow,f'{scnx_mailboxownerupn} ({', '.join(records_email)})') 
            print(arrow,f'{scnx_workemail} ({', '.join(records_email)})') 
            print(arrow, f'{scnx_accountname} ({', '.join(records_email)})') 
            print(arrow, f'{scnx_email_recipient} ({', '.join(records_email)})\n')
            print(colorama.Fore.RED + '[-] This query seeks to identify queried values ​​organized by the values ​​of the queried metakey\n' + colorama.Style.RESET_ALL)
            print(arrow, f'{scnx_mailboxownerupn} ({', '.join(records_email)}) {stats} {scnx_mailboxownerupn_without}') 
            print(arrow, f'{scnx_workemail} ({', '.join(records_email)}) {stats} {scnx_workemail_without}') 
            print(arrow, f'{scnx_accountname} ({', '.join(records_email)}) {stats} {scnx_accountname_without}')
            print(arrow, f'{scnx_email_recipient} ({', '.join(records_email)}) {stats} {scnx_email_recipient_only}\n')


def email_rsa_l(arguments):

        if not email(arguments.input):
            print(colorama.Fore.RED + '[!] Not found email address' + colorama.Style.RESET_ALL)
        else:
            records_email = []
            rsa_email = siem.rsa_email()
            found_email = email(args.input)

            while len(found_email) >= 2:

                for index in found_email:
                    records_email.append("'" + index + "'")
                    meadle = len(records_email) // 2
                    new1 = records_email[:meadle]
                    new2 = records_email[meadle:]

                print(colorama.Fore.GREEN + '[+] EXCHANGE\n' + colorama.Style.RESET_ALL)
                color = ' || ' + colorama.Fore.BLUE + ' email = ' + colorama.Style.RESET_ALL
                print(f'{rsa_email} {color.join(new1)}\n')  
                color = ' || ' + colorama.Fore.BLUE + ' email = ' + colorama.Style.RESET_ALL
                print(f'{rsa_email} {color.join(new2)}\n')

                break

            if len(found_email) < 2:                    
                print(colorama.Fore.RED + 'The -l or --l argument only accepts values ​​equal to or greater than 2, possibly the source does not have more than one value or cannot be extracted correctly\n' + colorama.Style.RESET_ALL)


def email_rsa(arguments):

        if not email(arguments.input):
            print(colorama.Fore.RED + '[!] Not found email address' + colorama.Style.RESET_ALL)
        else:
            records_email = []
            rsa_email = siem.rsa_email()
            found_email = email(args.input)

            for index in found_email:
                records_email.append("'" + index + "'")

            print(colorama.Fore.GREEN + '[+] EXCHANGE\n' + colorama.Style.RESET_ALL)
            color = ' || ' + colorama.Fore.BLUE + ' email = ' + colorama.Style.RESET_ALL
            print(f'{rsa_email} {color.join(records_email)}\n')  


def email_only(arguments):

        if not email(arguments.input):
            print(colorama.Fore.RED + '[!] Not found email address' + colorama.Style.RESET_ALL)
        else:
            print(colorama.Fore.GREEN + '[+] Emails\n' + colorama.Style.RESET_ALL)
            found_email = email(args.input)
            for index in set(found_email):
                print(index)


def reg_scnx_l(arguments):

    if not reg(arguments.input):
        print(colorama.Fore.RED + '[!] Not found windows registry' + colorama.Style.RESET_ALL)
    else:
        records_registry = []
        scnx_eventdata_only = siem.scnx_eventdata_only()
        found_registry = reg(arguments.input)
        stats = siem.scnx_stats()

        while len(found_registry) >= 2:

            for index in set(found_registry):
                records_registry.append(index)

                if args.include:
                        records_registry.extend(args.include)
                        records_registry = list(set(records_registry))
                
                if args.remove:
                    records_registry = [item for item in records_registry if item not in args.remove]
                    
                meadle = len(records_registry) // 2
                new1 = records_registry[:meadle]
                new2 = records_registry[meadle:]

            print(colorama.Fore.GREEN + '[+] Windows Registry Keys\n' + colorama.Style.RESET_ALL)

            eventdata_without = f' {colorama.Fore.BLUE + 'OR' + colorama.Style.RESET_ALL} {scnx_eventdata_only} contains'

            arrow = colorama.Fore.RED + '    ↳  ' + colorama.Style.RESET_ALL
            print(colorama.Fore.RED + '[-] This query seeks to identify the values ​​of Windows registry keys\n' + colorama.Style.RESET_ALL)
            print(arrow, f'{scnx_eventdata_only} contains {eventdata_without.join(new1)}')
            print(arrow, f'{scnx_eventdata_only} contains {eventdata_without.join(new2)}\n')
            print(colorama.Fore.RED + '[-] This query seeks to identify queried values ​​organized by the values ​​of the queried metakey\n' + colorama.Style.RESET_ALL)
            print(arrow, f'{scnx_eventdata_only} contains {eventdata_without.join(new1)}) {stats} {scnx_eventdata_only}')
            print(arrow, f'{scnx_eventdata_only} contains {eventdata_without.join(new2)}) {stats} {scnx_eventdata_only}\n')

            break

        if len(found_registry) < 2:                    
            print(colorama.Fore.RED + 'The -l or --l argument only accepts values ​​equal to or greater than 2, possibly the source does not have more than one value or cannot be extracted correctly\n'+ colorama.Style.RESET_ALL)


def reg_scnx(arguments):
            
    if not reg(arguments.input):
        print(colorama.Fore.RED + '[!] Not found Windows registry' + colorama.Style.RESET_ALL)
    else:
        records_registry = []
        scnx_eventdata_only = siem.scnx_eventdata_only()
        found_registry = reg(arguments.input)
        stats = siem.scnx_stats()

        for index in set(found_registry):
            records_registry.append(index)

            if args.include:
                        records_registry.extend(args.include)
                        records_registry = list(set(records_registry))
                
            if args.remove:
                records_registry = [item for item in records_registry if item not in args.remove] 

        arrow = colorama.Fore.RED + '    ↳  ' + colorama.Style.RESET_ALL
        print(colorama.Fore.GREEN + '[+] Windows Registry Keys\n' + colorama.Style.RESET_ALL)
        print(colorama.Fore.RED + '[-] This query seeks to identify the values ​​of Windows registry keys\n' + colorama.Style.RESET_ALL)     
        eventdata_without = f' {colorama.Fore.BLUE + 'OR' + colorama.Style.RESET_ALL} {scnx_eventdata_only} contains'   
        print(arrow, f'{scnx_eventdata_only} contains {eventdata_without.join(records_registry)}\n')
        print(colorama.Fore.RED + '[-] This query seeks to identify queried values ​​organized by the values ​​of the queried metakey\n' + colorama.Style.RESET_ALL)
        print(arrow, f'{scnx_eventdata_only} contains {eventdata_without.join(records_registry)}) {stats} {scnx_eventdata_only}\n')


def reg_rsa_l(arguments):
            
    if not reg(arguments.input):
        print(colorama.Fore.RED + '[!] Not found Windows registry' + colorama.Style.RESET_ALL)
    else:
        records_registry = []
        rsa_registry = siem.rsa_object_name()
        found_registry = reg(arguments.input)

        while len(found_registry) >= 2:

            for index in found_registry:
                records_registry.append("'" + index + "'")
                meadle = len(records_registry) // 2
                new1 = records_registry[:meadle]
                new2 = records_registry[meadle:]

            print(colorama.Fore.GREEN + '[+] Windows\n' + colorama.Style.RESET_ALL)
            color = ' || ' + colorama.Fore.BLUE + ' registry = ' + colorama.Style.RESET_ALL
            print(f'{rsa_registry} {color.join(new1)}\n')
            color = ' || ' + colorama.Fore.BLUE + ' registry = ' + colorama.Style.RESET_ALL
            print(f'{rsa_registry} {color.join(new2)}\n')

            break

        if len(found_registry) < 2:                    
            print(colorama.Fore.RED + 'The -l or --l argument only accepts values ​​equal to or greater than 2, possibly the source does not have more than one value or cannot be extracted correctly\n' + colorama.Style.RESET_ALL)


def reg_rsa(arguments):
                
    if not reg(arguments.input):
        print(colorama.Fore.RED + '[!] Not found Windows registry' + colorama.Style.RESET_ALL)
    else:
        records_registry = []
        rsa_registry = siem.rsa_object_name()
        found_registry = reg(arguments.input)

        for index in set(found_registry):
            records_registry.append(index)

        print(colorama.Fore.GREEN + '[+] Windows\n' + colorama.Style.RESET_ALL)
        color = ' || ' + colorama.Fore.BLUE + ' registry = ' + colorama.Style.RESET_ALL
        records_registry_two = [f"{registry}'" for registry in records_registry]
        print(f'{rsa_registry} {color.join(records_registry_two)}\n')


def extrair_cve(texto):
    match = re.search(r'CVE-\d{4}-\d{4,7}', texto)
    return match.group() if match else 'CVE não identificado'


def clean_description(texto):
    
    texto = re.sub(r"\*\*.*?\*\*", "", texto) 
    texto = re.sub(r"Assessed Attacker Value: \d+", "", texto)  
    texto = re.sub(r"\n+", "\n", texto)
    texto = re.sub(r"\s{2,}", " ", texto)
    return texto.strip()


def cve_details(cve_id):
    if not cve_id or "CVE" not in cve_id:
        print(f"[!] Ignorando resultado inválido: {cve_id}")
        return None

    url = f"https://vulners.com/api/v3/search/id/?id={cve_id}"

    try:
        response = requests.get(url, timeout=10)
        if response.status_code == 200:
            data = response.json()

            if data.get("result") != "OK":
                print(f"[!] Resposta inesperada da API para {cve_id}: {data.get('result')}")
                return None

            documents = data.get("data", {}).get("documents", {})
            doc = documents.get(cve_id)

            if not doc:
                print(f"[!] Documento da CVE {cve_id} response not found.")
                return None

            descricao = clean_description(doc.get("description", "Description not enable"))

            cvss_info = doc.get("cvss", {})
            cvss_v3 = cvss_info.get("cvssV3", {})

            score = cvss_v3.get("baseScore") or cvss_info.get("score", "N/A")
            severity = cvss_v3.get("baseSeverity", "N/A")

            if not score:
                score = "N/A"
            if not severity:
                severity = "N/A"

            
            severity_map = {
                "LOW": colorama.Fore.BLUE,
                "MEDIUM": colorama.Fore.YELLOW,
                "HIGH": colorama.Fore.RED,
                "CRITICAL": f"{colorama.Back.RED}{colorama.Fore.WHITE}"
            }

            cor_severidade = severity_map.get(severity.upper(), "")
            severity_colorida = f"{cor_severidade}{severity}{colorama.Style.RESET_ALL}"

            if isinstance(score, (int, float)) or (isinstance(score, str) and score.replace('.', '', 1).isdigit()):
                score_val = float(score)
                if score_val < 4.0:
                    score_colorida = f"{colorama.Fore.BLUE}{score_val}{colorama.Style.RESET_ALL}"
                elif score_val < 7.0:
                    score_colorida = f"{colorama.Fore.YELLOW}{score_val}{colorama.Style.RESET_ALL}"
                elif score_val < 9.0:
                    score_colorida = f"{colorama.Fore.RED}{score_val}{colorama.Style.RESET_ALL}"
                else:
                    score_colorida = f"{colorama.Back.RED}{colorama.Fore.WHITE}{score_val}{colorama.Style.RESET_ALL}"
            else:
                score_colorida = score

            return {
                "id": cve_id,
                "descricao": descricao,
                "cvss": score_colorida,
                "severity": severity_colorida
            }

        else:
            print(f"[!] Not possible get data for {cve_id} (status {response.status_code})")
            return None

    except requests.RequestException as e:
        print(f"[!] Consult error {cve_id}: {str(e)}")
        return None


def reg_only(arguments):

    if not reg(arguments.input):
        print(colorama.Fore.RED + '[!] Not found Windows registry' + colorama.Style.RESET_ALL)
    else:
        print(colorama.Fore.GREEN + '[+] Windows Registry Keys\n' + colorama.Style.RESET_ALL)
        found_reg = reg(arguments.input)
        for index in set(found_reg):
            print(index)  


def cve_exploitdb(found_cves):
    print(colorama.Fore.YELLOW + "\n[+] Checking for exploits in Exploit-DB...\n" + colorama.Style.RESET_ALL)

    for index in set(found_cves):
        exploit_link = find_exploit_cve(index)
        if exploit_link:
            print(
                colorama.Fore.GREEN + 
                f"[+] Exploit found for {index}" + 
                colorama.Style.RESET_ALL
            )
            arrow = colorama.Fore.BLUE + '    ↳  ' + colorama.Style.RESET_ALL
            print(arrow, f"Exploit link: {exploit_link}\n")
        else:
            print(
                colorama.Fore.RED + 
                f"[-] No Exploit found for {index}" + 
                colorama.Style.RESET_ALL
            )


def cve_only(arguments):
    found_cves = cve(arguments.input)

    if not found_cves:
        print(colorama.Fore.RED + '[!] Not found CVEs' + colorama.Style.RESET_ALL)
    else:
        
        if not arguments.cve_details:
            print(colorama.Fore.GREEN + '[+] CVEs\n' + colorama.Style.RESET_ALL)
            for index in set(found_cves):
                print(index)
    
    return found_cves


def check_analysis(cves, base_path='./CVE/'):
    cves_analyzed = {}
    cves_pending = []

    for cve in cves:
        cve_dir = os.path.join(base_path, cve)
        cve_file = os.path.join(cve_dir, "CVE.json")
        
        if os.path.exists(cve_file):
            try:
                with open(cve_file, 'r', encoding='utf-8') as file:
                    data = json.load(file)
                
                imagens = [
                    os.path.join(cve_dir, img)
                    for img in os.listdir(cve_dir)
                    if img.lower().endswith(('.png', '.jpg', '.jpeg'))
                ]
                data['imagens'] = imagens
                
                cves_analyzed[cve] = data
            except Exception as e:
                print(f"Error  process {cve_file}: {e}")
        else:
            cves_pending.append(cve)
    
    return cves_analyzed, cves_pending


class CVEReport(FPDF):
    def header(self):
        self.set_font('Arial', 'B', 12)
        self.cell(0, 10, 'Watching Killer Exploit Analysis', 0, 1, 'C')
        self.ln(10)
    
    
    def footer(self):
        self.set_y(-15)
        self.set_font('Arial', 'I', 8)
        self.cell(0, 10, f'Página {self.page_no()}', 0, 0, 'C')


def generator_report(cves_analyzed, cves_pending):
    pdf = CVEReport()

    pdf.add_page()
    pdf.image('./cover/cover.png', x=0, y=0, w=210, h=297)
    pdf.ln(10)


    for cve_id, data in cves_analyzed.items():
        pdf.add_page() 
        pdf.set_font('Arial', 'B', 16)
        pdf.cell(0, 10, f' {cve_id}', ln=True)
        pdf.ln(10)
        

        pdf.set_font('Arial', '', 12)
        pdf.multi_cell(0, 10, f'Descrição: {data.get("descricao", "N/A")}')
        pdf.ln(5)
        

        pdf.set_font('Arial', 'B', 12)
        pdf.cell(0, 10, 'Sugestões de Queries para Hunting:', ln=True)
        pdf.set_font('Arial', '', 12)
        for query in data.get('queries', []):
            pdf.multi_cell(0, 10, f' {query}')
            pdf.ln(2)
        pdf.ln(10)
        

        pdf.set_font('Arial', 'B', 12)
        pdf.cell(0, 10, 'Análises:', ln=True)
        for img_path in data.get('imagens', []):
            try:
                pdf.image(img_path, x=10, y=None, w=180)
                pdf.ln(10)
            except RuntimeError:
                pdf.cell(0, 10, f'Erro ao carregar imagem: {img_path}', ln=True)
    

    if cves_pending:
        pdf.add_page()
        pdf.set_font('Arial', 'B', 16)
        pdf.cell(0, 10, 'CVEs Pendentes de Análise:', ln=True)
        pdf.ln(10)
        
        pdf.set_font('Arial', '', 12)
        for cve in cves_pending:
            pdf.cell(0, 10, f'- {cve}', ln=True)
    
    file_name = f"Watching_Killer_CVE_Report.pdf"
    pdf.output(file_name)
    print(f"Relatório gerado: {file_name}")


if args.cvereport: 
    cves_extraidas = cve_with_report(args)
    if cves_extraidas:  
        cves_analyzed, cves_pending = check_analysis(cves_extraidas)
        generator_report(cves_analyzed, cves_pending)



def search_github(cve_id: str):
    try:
        token = os.getenv("githubtoken")
        if not token:
            print("[GitHub] githubtoken não configurado no .env.")
            return []

        headers = {
            "Accept": "application/vnd.github.v3+json",
            "Authorization": f"token {token}"
        }

        query = f"{cve_id}"
        #url = f"https://api.github.com/search/repositories?q={query}"
        url = f"https://api.github.com/search/repositories?q={query}+in:name,description,readme"

        response = requests.get(url, headers=headers, timeout=10)

        if response.status_code == 200:
            data = response.json()
            total_count = data.get("total_count", 0)
            if total_count > 0:
                return [{
                    "title": f"{total_count} repositories found",
                    "source": "GitHub",
                    "url": f"https://github.com/search?q={query}"
                }]
            else:
                return []
        else:
            print(f"[GitHub] Erro na API ({response.status_code}): {response.text}")
            return []

    except Exception as e:
        print(f"[GitHub] Erro inesperado: {e}")
        return []


if args.input and args.ip and args.securonix and args.l:
    ip_scnx_l(args)

elif args.input and args.ip and args.rsa and args.l:
    ip_rsa_l(args)

elif args.input and args.ip == True and args.rsa == True:
    ip_rsa(args)

elif args.input and args.ip == True and args.securonix == True:
    ip_scnx(args)

if args.input and args.ip == True and args.reputation == True:
    ip_with_reputation(args)

elif args.input and args.ip and not any([args.securonix, args.rsa]):
    ip_only(args)

elif args.input and args.domain and args.securonix and args.l:
    domain_scnx_l(args)

elif args.input and args.domain == True and args.securonix == True:
    domain_scnx(args)

elif args.input and args.domain and args.rsa and args.l:
    domain_rsa_l(args)

elif args.input and args.domain == True and args.rsa == True:
    domain_rsa(args)

elif args.input and args.domain == True:
    domain_only(args)

elif args.input and args.artifact and args.securonix and args.l:
    artifact_scnx_l(args)

elif args.input and args.artifact == True and args.securonix == True:
    artifact_scnx(args)

elif args.input and args.artifact and args.rsa and args.l:
    artifact_rsa_l(args)

elif args.input and args.artifact == True and args.rsa == True:
    artifact_rsa(args)

elif args.input and args.artifact:
    artifact_only(args)

elif args.input and args.md5 and args.securonix and args.l:
    md5_scnx_l(args)

elif args.input and args.md5 == True and args.securonix == True:
    md5_scnx(args)

elif args.input and args.md5 and args.rsa and args.l:
    md5_rsa_l(args)

elif args.input and args.md5 == True and args.rsa == True:
    md5_rsa(args)

elif args.input and args.md5 == True:
    md5_only(args)

elif args.input and args.sha1 and args.securonix and args.l:
    sha1_scnx_l(args)

elif args.input and args.sha1 == True and args.securonix == True:
    sha1_scnx(args)

elif args.input and args.sha1 and args.rsa and args.l:
    sha1_rsa_l(args)

elif args.input and args.sha1 == True and args.rsa == True:
    sha1_rsa(args)

elif args.input and args.sha1 == True:
    sha1_only(args)

elif args.input and args.sha256 and args.securonix and args.l:
    sha256_scnx_l(args)

elif args.input and args.sha256 == True and args.securonix == True:
    sha256_scnx(args)

elif args.input and args.sha256 and args.rsa and args.l:
    sha256_rsa_l(args)

elif args.input and args.sha256 == True and args.rsa == True:
    sha256_rsa(args)

elif args.input and args.sha256 == True:
    sha256_only(args)

elif args.input and args.email and args.securonix and args.l:
    email_scnx_l(args)

elif args.input and args.email == True and args.securonix == True:
    email_scnx(args)

elif args.input and args.email and args.rsa and args.l:
    email_rsa_l(args)

elif args.input and args.email == True and args.rsa == True:
    email_rsa(args)

elif args.input and args.email == True:
    email_only(args)

elif args.input and args.registry and args.securonix and args.l:
    reg_scnx_l(args)

elif args.input and args.registry and args.securonix:
    reg_scnx(args)

elif args.input and args.registry and args.rsa and args.l:
    reg_rsa_l(args)

elif args.input and args.registry and args.rsa:
    reg_rsa(args)

elif args.input and args.registry == True:
    reg_only(args)

elif args.input and args.github and args.cve:
    found_cves = cve_only(args)
    
    if found_cves:
        print(colorama.Fore.YELLOW + "\n[+] Searching for CVE-related repositories on GitHub...\n" + colorama.Style.RESET_ALL)
        for cve_id in found_cves:
            results = search_github(cve_id)
            
            if results:
                print(colorama.Fore.GREEN + f"[+] Repositories found for {cve_id}" + colorama.Style.RESET_ALL)
                for result in results:
                    seta = colorama.Fore.BLUE + '     ↳  ' + colorama.Style.RESET_ALL
                    print(seta, f"{result['title']}")
                    print(seta, f"{result['url']}\n")
            else:
                print(colorama.Fore.RED + f"[-] No repositories found for {cve_id}" + colorama.Style.RESET_ALL)
    

elif args.exploitdb and args.cve:
    found_cves = cve_only(args)  
    if found_cves:
        cve_exploitdb(found_cves) 

elif args.input and args.cve and args.cve_details:
    cve_list = cve_only(args)

    for cve_id in cve_list:
        resultado = cve_details(cve_id)
        if resultado:
            print("=" * 100)
            print(f"\nCVE: {resultado['id']}")
            print(f"CVSS: {resultado['cvss']}")
            print(f"DESCRIPTION: {resultado['descricao']}")
            

elif args.input and args.cve:
    cve_only(args)

elif args.input and args.cve == True and args.cvereport == True:
    cve_with_report(args)