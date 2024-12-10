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


load_dotenv(override=True)

abuseip = os.getenv("abuseipdbkey")

args = parsing.arguments()


def reg(arq):
    reg = []
    with open(arq, 'r', encoding="utf8") as outfile:
        reader = csv.reader(outfile)
        for raw in reader:
            for cell in raw: 
                matches = re.findall(r'((?:HKEY_LOCAL_MACHINE|HKEY_CURRENT_USER|HKEY_CLASSES_ROOT|HKEY_USERS|HKEY_CURRENT_CONFIG|HKLM|HKCU|HKCR|HKU|HKCC)(?:\\[\w\dçÇ]+)*(?:\\[\w\dçÇ]*(?:\r?\n[\w\d\\\\]+)*))', cell)
                reg.extend(matches)
    return set(reg)



def cve(arq):
    cve = []
    with open(arq, 'r', encoding="utf8") as outfile:
        reader = csv.reader(outfile)
        for raw in reader:
            for cell in raw:
                matches = re.findall(r'CVE-[\d]{4}-[\d]{,5}', cell)
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
                matches = re.findall(r'[0-9a-f]{32}', cell)
                hashes.extend(matches)
    return set(hashes)


def sha1(arq):
    hashes = []
    with open(arq, 'r', encoding="utf8") as outfile:
        reader = csv.reader(outfile)
        for raw in reader:
            for cell in raw:
                matches = re.findall(r'[0-9a-f]{40}', cell)
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
    tld = ['.com','.net','.br','.onion','.org','.gov', '.de', '.at', '.co','.link','.sh','.nz','.ua','.ch']
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
    process_extension = ['.exe','dll','.py','.vbs','.ps1','.bin','.bat','.wsf']
    with open(arq, 'r', encoding="utf8") as outfile:
        reader = csv.reader(outfile)
        for raw in reader:
            for cell in raw:
                matches = re.findall(r'\b(?:[a-zA-Z0-9-]+\.){1,}[a-zA-Z]{2,}\b', cell)
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


def option(arguments):

    if arguments.input and arguments.ip and arguments.scnx and arguments.l:

        if not ip(arguments.input):
            print(colorama.Fore.RED + 'Not found ip address' + colorama.Style.RESET_ALL )
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
                meadle = len(records_ip) // 2
                new1 = records_ip[:meadle]
                new2 = records_ip[meadle:]

            print('[AVs / EDRs / SOs]:\n')

            print(f'{scnx_source_address} ({', '.join(new1)})\n')

            print(f'{scnx_source_address} ({', '.join(new2)})\n')

            print(f'{scnx_destination_address} ({', '.join(new1)})\n')

            print(f'{scnx_destination_address} ({', '.join(new2)})\n')

            print(f'{scnx_source_address} ({', '.join(new1)}) {colorama.Fore.BLUE}OR{colorama.Style.RESET_ALL} {scnx_destination_address} ({', '.join(new1)})\n')

            print(f'{scnx_source_address} ({', '.join(new2)}) {colorama.Fore.BLUE}OR{colorama.Style.RESET_ALL} {scnx_destination_address} ({', '.join(new2)})\n')

            print(f'{scnx_source_address} ({', '.join(new1)}) {colorama.Fore.BLUE}OR{colorama.Style.RESET_ALL} {scnx_destination_address} ({', '.join(new1)}) {stats}{source_only}\n')

            print(f'{scnx_source_address} ({', '.join(new2)}) {colorama.Fore.BLUE}OR{colorama.Style.RESET_ALL} {scnx_destination_address} ({', '.join(new2)}) {stats}{source_only}\n')

            print(f'{scnx_source_address} ({', '.join(new1)}) {colorama.Fore.BLUE}OR{colorama.Style.RESET_ALL} {scnx_destination_address} ({', '.join(new1)}) {stats}{destination_only}\n')

            print(f'{scnx_source_address} ({', '.join(new2)}) {colorama.Fore.BLUE}OR{colorama.Style.RESET_ALL} {scnx_destination_address} ({', '.join(new2)}) {stats}{destination_only}\n')


    elif arguments.input and arguments.ip and arguments.rsa and arguments.l:

        if not ip(arguments.input):
            print(colorama.Fore.RED + 'Not found ip address' + colorama.Style.RESET_ALL)
        else:
            
            records_ip = []
            rsa_src_adress = siem.rsa_source_address()
            rsa_dst_adress = siem.rsa_destination_adress()
            found_ip = ip(args.input)

            for index in found_ip:
                records_ip.append(index)
                meadle = len(records_ip) // 2
                new1 = records_ip[:meadle]
                new2 = records_ip[meadle:]

            print('[AVs / EDRs / SOs]:\n')

            color = ' ||' + colorama.Fore.BLUE + ' ip.src = ' + colorama.Style.RESET_ALL
            print(f'{rsa_src_adress} {color.join(new1)} \n')

            color = ' ||' + colorama.Fore.BLUE + ' ip.src = ' + colorama.Style.RESET_ALL
            print(f'{rsa_src_adress} {color.join(new2)} \n')

            color = ' ||' + colorama.Fore.BLUE + ' ip.dst = ' + colorama.Style.RESET_ALL
            print(f'{rsa_dst_adress} {color.join(new1)} \n')

            color = ' ||' + colorama.Fore.BLUE + ' ip.dst = ' + colorama.Style.RESET_ALL
            print(f'{rsa_dst_adress} {color.join(new2)} \n')

            color = ' ||' + colorama.Fore.BLUE + ' ip.src = ' + colorama.Style.RESET_ALL
            print(f'{rsa_src_adress} {color.join(new1)} {colorama.Fore.BLUE} || {colorama.Style.RESET_ALL}', end='')

            color = ' ||' + colorama.Fore.BLUE + ' ip.dst = ' + colorama.Style.RESET_ALL
            print(f'{rsa_dst_adress} {color.join(new1)} {colorama.Fore.BLUE} {colorama.Style.RESET_ALL} \n')

            color = ' ||' + colorama.Fore.BLUE + ' ip.src = ' + colorama.Style.RESET_ALL
            print(f'{rsa_src_adress} {color.join(new2)} {colorama.Fore.BLUE} || {colorama.Style.RESET_ALL}', end='')

            color = ' ||' + colorama.Fore.BLUE + ' ip.dst = ' + colorama.Style.RESET_ALL
            print(f'{rsa_dst_adress} {color.join(new2)} {colorama.Fore.BLUE} {colorama.Style.RESET_ALL} \n')
                
    
    elif arguments.input and arguments.ip == True and arguments.scnx == True:
        if not ip(arguments.input):
            print(colorama.Fore.RED + 'Not found ip address' + colorama.Style.RESET_ALL)
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

            print('[AVs / EDRs / SOs]:\n')

            print(f'{scnx_source_address} ({', '.join(records_ip)})\n')

            print(f'{scnx_destination_address} ({', '.join(records_ip)})\n')

            print(f'{scnx_source_address} ({', '.join(records_ip)}) {colorama.Fore.BLUE}OR{colorama.Style.RESET_ALL} {scnx_destination_address} ({', '.join(records_ip)})\n')
                    
            print(f'{scnx_source_address} ({', '.join(records_ip)}) {colorama.Fore.BLUE}OR{colorama.Style.RESET_ALL} {scnx_destination_address} ({', '.join(records_ip)}) {stats}{source_only}\n')  

            print(f'{scnx_source_address} ({', '.join(records_ip)}) {colorama.Fore.BLUE}OR{colorama.Style.RESET_ALL} {scnx_destination_address} ({', '.join(records_ip)}) {stats}{destination_only}\n')
                 
            
    elif arguments.input and arguments.ip == True and arguments.rsa == True:

        if not ip(arguments.input):
            print(colorama.Fore.RED + 'Not found ip address' + colorama.Style.RESET_ALL)
        else:        
            records_ip = []
            rsa_src_adress = siem.rsa_source_address()
            rsa_dst_adress = siem.rsa_destination_adress()
            found_ip = ip(args.input)

            for index in found_ip:
                records_ip.append(index)

            print('[AVs / EDRs / SOs]:\n')

            color = ' ||' + colorama.Fore.BLUE + ' ip.src = ' + colorama.Style.RESET_ALL
            print(f'{rsa_src_adress} {color.join(records_ip)} \n')

            color = ' ||' + colorama.Fore.BLUE + ' ip.dst = ' + colorama.Style.RESET_ALL
            print(f'{rsa_dst_adress} {color.join(records_ip)} \n')

            color = ' ||' + colorama.Fore.BLUE + ' ip.src = ' + colorama.Style.RESET_ALL
            print(f'{rsa_src_adress} {color.join(records_ip)} {colorama.Fore.BLUE} || {colorama.Style.RESET_ALL}', end='')

            color = ' || ' + colorama.Fore.BLUE + ' ip.dst = ' + colorama.Style.RESET_ALL
            print(rsa_dst_adress, color.join(records_ip))
        

    elif arguments.input and arguments.ip == True and arguments.reputation == True:

        if not ip(arguments.input):
            print(colorama.Fore.RED + 'Not found ip address' + colorama.Style.RESET_ALL )
        else:        

            url = 'https://api.abuseipdb.com/api/v2/check'
            
            querystring = {
                'ipAddress': '0.0.0.0',
                'maxAgeInDays': '90'
                }
                    
            headers = {
                    'Accept': 'application/json',
                    'Key': ''
                }
            
            headers['Key'] = abuseip

            ip_parsing = ip(args.input)   


            for index in ip_parsing:
                querystring["ipAddress"] = index

                try:
                    response = requests.request(method='GET', url=url, headers=headers, params=querystring)
                    decodedResponse = json.loads(response.text)
                    address = decodedResponse['data']['ipAddress']
                    rep = decodedResponse['data']['abuseConfidenceScore']
                    dns = decodedResponse['data']['hostnames']
                except KeyError:
                    print("There's probably something wrong with the API key. Check if it's the right one and try again. Also, check if the file is named .env.",'\n')
                    break

                ip_parsing = list(set(ip_parsing))

                if not dns:
                    if rep >= 0 and rep <= 25:   
                        rep2 = str(rep) + '%'             
                        print(f'{address} {colorama.Fore.GREEN + rep2 + colorama.Style.RESET_ALL }')

                    elif rep >= 26 and rep <= 50:
                        rep2 = str(rep) + '%'
                        print(f'{address} {colorama.Fore.BLUE + rep2 + colorama.Style.RESET_ALL}')

                    elif rep >= 51 and rep <= 75:
                        rep2 = str(rep) + '%'
                        print(f'{address} {colorama.Fore.YELLOW + rep2 + colorama.Style.RESET_ALL }')
                    
                    elif rep >= 76 and rep <= 100:
                        rep2 = str(rep) + '%'
                        print(f'{address} {colorama.Fore.RED + rep2 + colorama.Style.RESET_ALL }')

                elif rep >= 0 and rep <= 25:   
                    rep2 = str(rep) + '%'             
                    print(f'{address} {colorama.Fore.GREEN + rep2 + colorama.Style.RESET_ALL } {dns} ')

                elif rep >= 26 and rep <= 50:   
                    rep2 = str(rep) + '%'             
                    print(f'{address} {colorama.Fore.BLUE + rep2 + colorama.Style.RESET_ALL } {dns} ')

                elif rep >= 51 and rep <= 75:
                    rep2 = str(rep) + '%'
                    print(f'{address} {colorama.Fore.YELLOW + rep2 + colorama.Style.RESET_ALL } {dns} ')
                    
                elif rep >= 76 and rep <= 100:
                    rep2 = str(rep) + '%'
                    print(f'{address} {colorama.Fore.RED + rep2 + colorama.Style.RESET_ALL } {dns} ')       
            

    elif arguments.input and arguments.ip == True:

        if not ip(arguments.input):
            print(colorama.Fore.RED + 'Not found ip address' + colorama.Style.RESET_ALL)
        else:        
            found_ip = ip(args.input)
            for index in set(found_ip):
                print(index)


    elif arguments.input and arguments.domain and arguments.scnx and arguments.l:
    
        if not domain(arguments.input):
            print('Not found domain address' + colorama.Style.RESET_ALL)
        else:

            records_domain = []
            scnx_request_url = siem.scnx_request_url()
            scnx_request_only = siem.scnx_request_url_only()
            stats = siem.scnx_stats()
            found_domain = domain(args.input)

            for index in found_domain:
                records_domain.append(index)
                meadle = len(records_domain) // 2
                new1 = records_domain[:meadle]
                new2 = records_domain[meadle:]
                
            
            print('[NGFW / WAF / PROXY]:\n')
            
            print(f'{scnx_request_url} ({', '.join(new1)})\n')

            print(f'{scnx_request_url} ({', '.join(new2)})\n')

            print(f'{scnx_request_url} ({', '.join(new1)}) {stats}{scnx_request_only}\n')

            print(f'{scnx_request_url} ({', '.join(new2)}) {stats}{scnx_request_only}\n')

            domain_without = f' OR {scnx_request_only} contains '

            print(f'{scnx_request_only} contains {domain_without.join(new1)}\n')

            print(f'{scnx_request_only} contains {domain_without.join(new2)}\n')

            print(f'{scnx_request_only} contains {domain_without.join(new1)} {stats}{scnx_request_only}\n')

            print(f'{scnx_request_only} contains {domain_without.join(new2)} {stats}{scnx_request_only}\n')


    elif arguments.input and arguments.domain == True and arguments.scnx == True:

        if not domain(arguments.input):
            print(colorama.Fore.RED + 'Not found domain address' + colorama.Style.RESET_ALL)
        else:
            records_domain = []
            scnx_request_url = siem.scnx_request_url()
            scnx_request_only = siem.scnx_request_url_only()
            scnx_email_recipient_domain = siem.scnx_email_recipient_domain()
            scnx_email_recipient_domain_only = siem.scnx_email_recipient_domain_only()
            stats = siem.scnx_stats()
            found_domain = domain(args.input)

            for index in found_domain:
                records_domain.append(index)

            print('[NGFW / WAF / PROXY / EXCHANGE]:\n')

            print(f'{scnx_request_url} ({', '.join(records_domain)})\n')

            print(f'{scnx_email_recipient_domain} ({', '.join(records_domain)})\n')

            domain_without = f' OR {scnx_request_only} contains '

            print(f'{scnx_request_only} contains {domain_without.join(records_domain)}\n')

            print(f'{scnx_request_url} ({', '.join(records_domain)}) {stats}{scnx_request_only}\n')

            print(f'{scnx_email_recipient_domain} ({', '.join(records_domain)}) {stats}{scnx_email_recipient_domain_only}')


    elif arguments.input and arguments.domain and arguments.rsa and arguments.l:

        if not domain(arguments.input):
            print(colorama.Fore.RED + 'Not found domain address' + colorama.Style.RESET_ALL)
        else:   
            records_domain = []
            rsa_url = siem.rsa_url()
            found_domain = domain(args.input)

            for index in found_domain:
                records_domain.append("'" + index + "'")
                meadle = len(records_domain) // 2
                new1 = records_domain[:meadle]
                new2 = records_domain[meadle:]

                
            print('[NGFW / WAF / PROXY]:\n')

            color = ' ||' + colorama.Fore.BLUE + ' url = ' + colorama.Style.RESET_ALL 
            print(f'{rsa_url} {color.join(new1)}\n')

            color = ' ||' + colorama.Fore.BLUE + ' url = ' + colorama.Style.RESET_ALL
            print(f'{rsa_url} {color.join(new2)}')


    elif arguments.input and arguments.domain == True and arguments.rsa == True:

        if not domain(arguments.input):
            print(colorama.Fore.RED + 'Not found domain address' + colorama.Style.RESET_ALL)
        else:   
            records_domain = []
            rsa_url = siem.rsa_url()
            found_domain = domain(args.input)

            for index in found_domain:
                records_domain.append("'" + index + "'")
                
            print('[NGFW / WAF / PROXY]:\n')

            color = ' ||' + colorama.Fore.BLUE + ' url = ' + colorama.Style.RESET_ALL
            print(f'{rsa_url} {color.join(records_domain)}')


    elif arguments.input and arguments.domain == True:

        if not domain(arguments.input):
            print(colorama.Fore.RED + 'Not found domain address' + colorama.Style.RESET_ALL)
        else:        
            found_domain = domain(args.input)
            for index in set(found_domain):
                print(index)
        
    
    elif arguments.input and arguments.artifact and arguments.scnx and arguments.l:

        if not artifact(arguments.input):
            print(colorama.Fore.RED + 'Not found artifact' + colorama.Style.RESET_ALL)
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
            stats = siem.scnx_stats()

            for index in found_artifact:
                records_artifact.append(index)
                meadle = len(records_artifact) // 2
                new1 = records_artifact[:meadle]
                new2 = records_artifact[meadle:]

            print('[AVS / EDRS / Windows / Linux]:\n')

            print(f'{scnx_sourceprocessname} ({', '.join(new1)})\n')

            print(f'{scnx_sourceprocessname} ({', '.join(new2)})\n')

            print(f'{scnx_destination_process_name} ({', '.join(new1)})\n')

            print(f'{scnx_destination_process_name} ({', '.join(new2)})\n')

            print(f'{scnx_sourceprocessname} ({', '.join(new1)}) {colorama.Fore.BLUE}OR{colorama.Style.RESET_ALL} {scnx_destination_process_name} ({', '.join(new1)})\n')

            print(f'{scnx_sourceprocessname} ({', '.join(new2)}) {colorama.Fore.BLUE}OR{colorama.Style.RESET_ALL} {scnx_destination_process_name} ({', '.join(new2)})\n')

            print(f'{scnx_filename} ({', '.join(new1)})\n')

            print(f'{scnx_filename} ({', '.join(new2)})\n')

            print(f'{scnx_filename} ({', '.join(new1)}) {stats} {scnx_file_name_only}\n')

            print(f'{scnx_filename} ({', '.join(new2)}) {stats} {scnx_file_name_only}\n')

            print(f'{scnx_sourceprocessname} ({', '.join(new1)}) {stats} {scnx_source_process_name_only} {command_line_only}\n')

            print(f'{scnx_sourceprocessname} ({', '.join(new2)}) {stats} {scnx_source_process_name_only} {command_line_only}\n')

            print(f'{scnx_destination_process_name} ({', '.join(new1)}) {stats} {scnx_destination_process_name_only} {command_line_only}\n')

            print(f'{scnx_destination_process_name} ({', '.join(new2)}) {stats} {scnx_destination_process_name_only} {command_line_only}\n')

        
    elif arguments.input and arguments.artifact and arguments.rsa and arguments.l:

        if not artifact(arguments.input):
            print(colorama.Fore.RED + 'Not found artifact' + colorama.Style.RESET_ALL)
        else:        

            records_artifact = []
            rsa_process = siem.process_contains()
            found_artifact = artifact(args.input)

            for index in found_artifact:
                records_artifact.append("'" + index + "'")
                meadle = len(records_artifact) // 2
                new1 = records_artifact[:meadle]
                new2 = records_artifact[meadle:]


            print('[AVS / EDRS / Windows / Linux]:\n')

            color = ' ||' + colorama.Fore.BLUE + ' process contains ' + colorama.Style.RESET_ALL
            print(f'{rsa_process} {color.join(new1)}\n')

            color = ' ||' + colorama.Fore.BLUE + ' process contains ' + colorama.Style.RESET_ALL
            print(f'{rsa_process} {color.join(new2)}')


    elif arguments.input and arguments.artifact == True and arguments.scnx == True:

        if not artifact(arguments.input):
            print(colorama.Fore.RED + 'Not found artifact' + colorama.Style.RESET_ALL)
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
            stats = siem.scnx_stats()

            for index in found_artifact:
                records_artifact.append(index)
                
            print('[AVS / EDRS / Windows / Linux]:\n')

            print(f'{scnx_sourceprocessname} ({', '.join(records_artifact)})\n')

            print(f'{scnx_destination_process_name} ({', '.join(records_artifact)})\n')

            print(f'{scnx_sourceprocessname} ({', '.join(records_artifact)}) {colorama.Fore.BLUE}OR{colorama.Style.RESET_ALL} {scnx_destination_process_name} ({', '.join(records_artifact)})\n')

            print(f'{scnx_filename} ({', '.join(records_artifact)})\n')

            print(f'{scnx_filename} ({', '.join(records_artifact)}) {stats} {scnx_file_name_only}\n')

            print(f'{scnx_sourceprocessname} ({', '.join(records_artifact)}) {stats} {scnx_source_process_name_only} {command_line_only}\n')

            print(f'{scnx_destination_process_name} ({', '.join(records_artifact)}) {stats} {scnx_destination_process_name_only} {command_line_only}\n')

            print(f'{scnx_sourceprocessname} ({', '.join(records_artifact)}) {stats} {scnx_source_process_name_only} {scnx_destination_process_name_only} {command_line_only}\n')
            
           
    elif arguments.input and arguments.artifact == True and arguments.rsa == True:

        if not artifact(arguments.input):
            print(colorama.Fore.RED + 'Not found artifact' + colorama.Style.RESET_ALL)
        else:        

            records_artifact = []
            rsa_process = siem.process_contains()
            found_artifact = artifact(args.input)

            for index in found_artifact:
                records_artifact.append("'" + index + "'")

            print('[AVS / EDRS / Windows / Linux]:\n')

            color = ' ||' + colorama.Fore.BLUE + ' process contains ' + colorama.Style.RESET_ALL
            print(f'{rsa_process} {color.join(records_artifact)}')


    elif arguments.input and arguments.artifact:

        if not artifact(arguments.input):
            print(colorama.Fore.RED + 'Not found artifact' + colorama.Style.RESET_ALL)
        else:
            found_artifact = artifact(args.input)
            for index in set(found_artifact):
                print(index)


    elif arguments.input and arguments.md5 and arguments.scnx and arguments.l:

        if not md5(arguments.input):
            print(colorama.Fore.RED + 'Not found md5 hashes' + colorama.Style.RESET_ALL)
        else:        
            records_md5 = []
            scnx_old_file_hash = siem.scnx_old_file_hash()
            found_md5 = md5(args.input)

            for index in found_md5:
                records_md5.append(index)
                meadle = len(records_md5) // 2
                new1 = records_md5[:meadle]
                new2 = records_md5[meadle:]

            print('[AVs / EDRs]:\n')

            print(f'{scnx_old_file_hash} ({', '.join(new1)})\n')

            print(f'{scnx_old_file_hash} ({', '.join(new2)})')

    
    elif arguments.input and arguments.md5 and arguments.rsa and arguments.l:

        if not md5(arguments.input):
            print(colorama.Fore.RED + 'Not found md5 hashes' + colorama.Style.RESET_ALL)
        else:        
            records_md5 = []
            rsa_checksum = siem.rsa_cheksum()
            found_checksum = md5(args.input)

            for index in found_checksum:
                records_md5.append(index)
                meadle = len(records_md5) // 2
                new1 = records_md5[:meadle]
                new2 = records_md5[meadle:]

            print('[AVs / EDRs]:\n')

            color = ' ||' + colorama.Fore.BLUE + ' checksum = ' + colorama.Style.RESET_ALL + "'"
            records_md5_two = [f"{sha256}'" for sha256 in new1]
            print(f'{rsa_checksum} {color.join(records_md5_two)} \n')

            color = ' ||' + colorama.Fore.BLUE + ' checksum = ' + colorama.Style.RESET_ALL + "'"
            records_md5_two = [f"{sha256}'" for sha256 in new2]
            print(f'{rsa_checksum} {color.join(records_md5_two)} \n') 

            print('[Sysmon]\n')

            color = ' ||' + colorama.Fore.BLUE + ' checksum = ' + colorama.Style.RESET_ALL + "'md5="
            records_md5_two = [f"{md5}'" for md5 in new1]        
            print(f"{rsa_checksum} 'md5={color.join(records_md5_two)}\n")

            color = ' ||' + colorama.Fore.BLUE + ' checksum = ' + colorama.Style.RESET_ALL + "'md5="
            records_md5_two = [f"{md5}'" for md5 in new2]        
            print(f"{rsa_checksum} 'md5={color.join(records_md5_two)}")


    elif arguments.input and arguments.md5 == True and arguments.scnx == True:

        if not md5(arguments.input):
            print(colorama.Fore.RED + 'Not found md5 hashes' + colorama.Style.RESET_ALL)
        else:        
            records_md5 = []
            scnx_old_file_hash = siem.scnx_old_file_hash()
            found_md5 = md5(args.input)

            for index in found_md5:
                records_md5.append(index)

            print('[AVs / EDRs]:\n')
            print(f'{scnx_old_file_hash} ({', '.join(records_md5)})')


    elif arguments.input and arguments.md5 == True and arguments.rsa == True:

        if not md5(arguments.input):
            print(colorama.Fore.RED + 'Not found md5 hashes' + colorama.Style.RESET_ALL)
        else:        
            records_md5 = []
            rsa_checksum = siem.rsa_cheksum()
            found_checksum = md5(args.input)

            for index in found_checksum:
                records_md5.append(index)

            print('[AVs / EDRs]:\n')

            color = ' ||' + colorama.Fore.BLUE + ' checksum = ' + colorama.Style.RESET_ALL + "'"
            records_md5_two = [f"{md5}'" for md5 in records_md5]
            print(f'{rsa_checksum} \'{color.join(records_md5_two)} \n') 

            print('[Sysmon]\n')

            color = ' ||' + colorama.Fore.BLUE + ' checksum = ' + colorama.Style.RESET_ALL + "'md5="
            records_md5 = [f"{md5}'" for md5 in records_md5]        
            print(f"{rsa_checksum} 'md5={color.join(records_md5)}")
                        
           
 
    elif arguments.input and arguments.md5 == True:

        if not md5(arguments.input):
            print(colorama.Fore.RED + 'Not found md5 hashes' + colorama.Style.RESET_ALL)
        else:        
            found_md5 = md5(args.input)

            for index in set(found_md5):
                print(index)

    
    elif arguments.input and arguments.sha1 and arguments.scnx and arguments.l:

        if not sha1(arguments.input):
            print(colorama.Fore.RED + 'Not found sha1 hashes' + colorama.Style.RESET_ALL)
        else:        
            records_sha1 = []
            scnx_old_file_hash = siem.scnx_old_file_hash()
            found_sha1 = sha1(args.input)
            
            for index in found_sha1:
                records_sha1.append(index)
                meadle = len(records_sha1) // 2
                new1 = records_sha1[:meadle]
                new2 = records_sha1[meadle:]


            print('[AVs / EDRs]:\n')

            print(f'{scnx_old_file_hash} ({', '.join(new1)})\n')

            print(f'{scnx_old_file_hash} ({', '.join(new2)})')


    elif arguments.input and arguments.sha1 and arguments.rsa and arguments.l:

        if not sha1(arguments.input):
            print(colorama.Fore.RED + 'Not found sha1 hashes' + colorama.Style.RESET_ALL)
        else:        
            records_sha1 = []
            rsa_checksum = siem.rsa_cheksum()
            found_checksum = sha1(args.input)

            for index in found_checksum:
                records_sha1.append(index)
                meadle = len(records_sha1) // 2
                new1 = records_sha1[:meadle]
                new2 = records_sha1[meadle:]

            print('[AVs / EDRs]:\n')
            
            color = ' || ' + colorama.Fore.BLUE + ' checksum = ' + colorama.Style.RESET_ALL + "'"
            records_sha1_two = [f"{sha1}'" for sha1 in new1]
            print(f'{rsa_checksum} {color.join(records_sha1_two)}\n')  

            color = ' || ' + colorama.Fore.BLUE + ' checksum = ' + colorama.Style.RESET_ALL + "'"
            records_sha1_two = [f"{sha1}'" for sha1 in new2]
            print(f'{rsa_checksum} {color.join(records_sha1_two)}\n')

            print('[Sysmon]\n')

            color = ' ||' + colorama.Fore.BLUE + ' checksum = ' + colorama.Style.RESET_ALL + "'sha1="
            records_sha1_two = [f"{sha1}'" for sha1 in new1]
            print(f"{rsa_checksum} 'sha1={color.join(records_sha1_two)}\n")

            color = ' ||' + colorama.Fore.BLUE + ' checksum = ' + colorama.Style.RESET_ALL + "'sha1="
            records_sha1_two = [f"{sha1}'" for sha1 in new2]
            print(f"{rsa_checksum} 'sha1={color.join(records_sha1_two)}")


    elif arguments.input and arguments.sha1 == True and arguments.scnx == True:

        if not sha1(arguments.input):
            print(colorama.Fore.RED + 'Not found sha1 hashes' + colorama.Style.RESET_ALL)
        else:        
            records_sha1 = []
            scnx_old_file_hash = siem.scnx_old_file_hash()
            found_sha1 = sha1(args.input)

            for index in found_sha1:
                records_sha1.append(index)

            print('[AVs / EDRs]:\n')

            print(f'{scnx_old_file_hash} ({', '.join(records_sha1)})')

    
    elif arguments.input and arguments.sha1 == True and arguments.rsa == True:

        if not sha1(arguments.input):
            print(colorama.Fore.RED + 'Not found sha1 hashes' + colorama.Style.RESET_ALL)
        else:        
            records_sha1 = []
            rsa_checksum = siem.rsa_cheksum()
            found_checksum = sha1(args.input)

            for index in found_checksum:
                records_sha1.append(index)

            print('[AVs / EDRs]:\n')
            
            color = ' || ' + colorama.Fore.BLUE + ' checksum = ' + colorama.Style.RESET_ALL + "'"
            records_sha1_two = [f"{sha1}'" for sha1 in records_sha1]
            print(f'{rsa_checksum} \'{color.join(records_sha1_two)}\n')  

            print('[Sysmon]\n')

            color = ' ||' + colorama.Fore.BLUE + ' checksum = ' + colorama.Style.RESET_ALL + "'sha1="
            records_sha1 = [f"{sha1}'" for sha1 in records_sha1]
            print(f"{rsa_checksum} 'sha1={color.join(records_sha1)}") 


    elif arguments.input and arguments.sha1 == True:

        if not sha1(arguments.input):
            print(colorama.Fore.RED + 'Not found sha1 hashes' + colorama.Style.RESET_ALL)
        else:        
            found_sha1 = sha1(args.input)
            for index in set(found_sha1):
                print(index)


    elif arguments.input and arguments.sha256 and arguments.scnx and arguments.l:

        if not sha256(arguments.input):
            print(colorama.Fore.RED + 'Not found sha256 hashes' + colorama.Style.RESET_ALL)
        else:
            records_sha256 = []
            scnx_old_file_hash = siem.scnx_old_file_hash()
            found_sha256 = sha256(arguments.input)

            for index in set(found_sha256):
                records_sha256.append(index)
                meadle = len(records_sha256) // 2
                new1 = records_sha256[:meadle]
                new2 = records_sha256[meadle:]

            print('[AVs / EDRs]:\n')

            print(f'{scnx_old_file_hash} ({', '.join(new1)})\n')   

            print(f'{scnx_old_file_hash} ({', '.join(new2)})') 


    elif arguments.input and arguments.sha256 and arguments.rsa and arguments.l:

        if not sha256(arguments.input):
            print(colorama.Fore.RED + 'Not found sha256 hashes' + colorama.Style.RESET_ALL)
        else:
            records_sha256 = []
            rsa_checksum = siem.rsa_cheksum()
            found_checksum = sha256(args.input)

            for index in found_checksum:
                records_sha256.append(index)
                meadle = len(records_sha256) // 2
                new1 = records_sha256[:meadle]
                new2 = records_sha256[meadle:]

            print('[AVs / EDRs]:\n')

            color = ' || ' + colorama.Fore.BLUE + ' checksum = ' + colorama.Style.RESET_ALL + "'"
            records_sha256_two = [f"{sha256}'" for sha256 in new1]
            print(f'{rsa_checksum} {color.join(records_sha256_two)}\n')  

            color = ' || ' + colorama.Fore.BLUE + ' checksum = ' + colorama.Style.RESET_ALL+ "'"
            records_sha256_two = [f"{sha256}'" for sha256 in new2]
            print(f'{rsa_checksum} {color.join(records_sha256_two)}\n')

            print('[Sysmon]\n')

            color = ' ||' + colorama.Fore.BLUE + ' checksum = ' + colorama.Style.RESET_ALL + "'sha256="
            records_sha256_two = [f"{sha256}'" for sha256 in new1]
            print(f"{rsa_checksum} 'sha256={color.join(records_sha256_two)}\n") 

            color = ' ||' + colorama.Fore.BLUE + ' checksum = ' + colorama.Style.RESET_ALL + "'sha256="
            records_sha256_two = [f"{sha256}'" for sha256 in new2]
            print(f"{rsa_checksum} 'sha256={color.join(records_sha256_two)}") 


    elif arguments.input and arguments.sha256 == True and arguments.scnx == True:

        if not sha256(arguments.input):
            print(colorama.Fore.RED + 'Not found sha256 hashes' + colorama.Style.RESET_ALL)
        else:
            records_sha256 = []
            scnx_old_file_hash = siem.scnx_old_file_hash()
            found_sha256 = sha256(arguments.input)

            for index in set(found_sha256):
                records_sha256.append(index)

            print('[AVs / EDRs]:\n')

            print(f'{scnx_old_file_hash} ({', '.join(records_sha256)})')   
        
    
    elif arguments.input and arguments.sha256 == True and arguments.rsa == True:

        if not sha256(arguments.input):
            print(colorama.Fore.RED + 'Not found sha256 hashes' + colorama.Style.RESET_ALL)
        else:
            records_sha256 = []
            rsa_checksum = siem.rsa_cheksum()
            found_checksum = sha256(args.input)

            for index in found_checksum:
                records_sha256.append(index)
                

            print('[AVs / EDRs]:\n')

            color = ' || ' + colorama.Fore.BLUE + ' checksum = ' + colorama.Style.RESET_ALL + "'"
            records_sha256_two = [f"{sha256}'" for sha256 in records_sha256]
            print(f'{rsa_checksum} \'{color.join(records_sha256_two)}\n')  

            print('[Sysmon]\n')

            color = ' ||' + colorama.Fore.BLUE + ' checksum = ' + colorama.Style.RESET_ALL + "'sha256="
            records_sha256 = [f"{sha256}'" for sha256 in records_sha256]
            print(f"{rsa_checksum} 'sha256={color.join(records_sha256)}") 
        

    elif arguments.input and arguments.sha256 == True:

        if not sha256(arguments.input):
            print(colorama.Fore.RED + 'Not found sha256 hashes' + colorama.Style.RESET_ALL)
        else:
            found_sha256 = sha256(args.input)
            for index in set(found_sha256):
                print(index)


    elif arguments.input and arguments.email and arguments.scnx and arguments.l:

        if not email(arguments.input):
            print(colorama.Fore.RED + 'Not found email address' + colorama.Style.RESET_ALL)
        else:
            records_email = []
            scnx_mailboxownerupn = siem.scnx_mailboxownerupn()
            scnx_mailboxownerupn_without = siem.scnx_mailboxownerupn_without()
            scnx_workemail = siem.scnx_workemail()
            scnx_workemail_without = siem.scnx_workemail_without() 
            scnx_accountname = siem.scnx_accountname()
            scnx_accountname_without = siem.scnx_accountname_without()
            found_email = email(arguments.input)
            stats = siem.scnx_stats()

            for index in set(found_email):
                records_email.append(index)
                meadle = len(records_email) // 2
                new1 = records_email[:meadle]
                new2 = records_email[meadle:]

            print('[EXCHANGE]:\n')

            print(f'{scnx_mailboxownerupn} ({', '.join(new1)})\n')   

            print(f'{scnx_mailboxownerupn} ({', '.join(new2)})\n')

            print(f'{scnx_accountname} ({', '.join(new1)})\n')   

            print(f'{scnx_accountname} ({', '.join(new2)})\n')

            print(f'{scnx_workemail} ({', '.join(new1)})\n') 

            print(f'{scnx_workemail} ({', '.join(new2)})\n') 

            print(f'{scnx_mailboxownerupn} ({', '.join(new1)}) {stats} {scnx_mailboxownerupn_without}\n')   

            print(f'{scnx_mailboxownerupn} ({', '.join(new2)}) {stats} {scnx_mailboxownerupn_without}\n')

            print(f'{scnx_accountname} ({', '.join(new1)}) {stats} {scnx_accountname_without}\n')   

            print(f'{scnx_accountname} ({', '.join(new2)}) {stats} {scnx_accountname_without}\n')

            print(f'{scnx_workemail} ({', '.join(new1)}) {stats} {scnx_workemail_without}\n')   

            print(f'{scnx_workemail} ({', '.join(new2)}) {stats} {scnx_workemail_without}\n')


    elif arguments.input and arguments.email and arguments.rsa and arguments.l:

        if not email(arguments.input):
            print(colorama.Fore.RED + 'Not found email address' + colorama.Style.RESET_ALL)
        else:
            records_email = []
            rsa_email = siem.rsa_email()
            found_email = email(args.input)

            for index in found_email:
                records_email.append("'" + index + "'")
                meadle = len(records_email) // 2
                new1 = records_email[:meadle]
                new2 = records_email[meadle:]

            print('[EXCHANGE]\n')

            color = ' || ' + colorama.Fore.BLUE + ' email = ' + colorama.Style.RESET_ALL
            print(f'{rsa_email} {color.join(new1)}\n')  

            color = ' || ' + colorama.Fore.BLUE + ' email = ' + colorama.Style.RESET_ALL
            print(f'{rsa_email} {color.join(new2)}\n')


    elif arguments.input and arguments.email == True and arguments.scnx == True:

        if not email(arguments.input):
            print(colorama.Fore.RED + 'Not found email address' + colorama.Style.RESET_ALL)
        else:
            records_email = []
            scnx_mailboxownerupn = siem.scnx_mailboxownerupn()
            scnx_mailboxownerupn_without = siem.scnx_mailboxownerupn_without()
            scnx_workemail = siem.scnx_workemail()
            scnx_workemail_without = siem.scnx_workemail_without() 
            scnx_accountname = siem.scnx_accountname()
            scnx_accountname_without = siem.scnx_accountname_without()
            found_email = email(arguments.input)
            stats = siem.scnx_stats()

            for index in set(found_email):
                records_email.append(index)

            print('[EXCHANGE]:\n')

            print(f'{scnx_mailboxownerupn} ({', '.join(records_email)})\n') 

            print(f'{scnx_workemail} ({', '.join(records_email)})\n') 

            print(f'{scnx_accountname} ({', '.join(records_email)})\n') 

            print(f'{scnx_mailboxownerupn} ({', '.join(records_email)}) {stats} {scnx_mailboxownerupn_without}\n') 

            print(f'{scnx_workemail} ({', '.join(records_email)}) {stats} {scnx_workemail_without}\n') 

            print(f'{scnx_accountname} ({', '.join(records_email)}) {stats} {scnx_accountname_without}\n')

    
    elif arguments.input and arguments.email == True and arguments.rsa == True:

        if not email(arguments.input):
            print(colorama.Fore.RED + 'Not found email address' + colorama.Style.RESET_ALL)
        else:
            records_email = []
            rsa_email = siem.rsa_email()
            found_email = email(args.input)

            for index in found_email:
                records_email.append("'" + index + "'")

            print('[EXCHANGE]:\n')

            color = ' || ' + colorama.Fore.BLUE + ' email = ' + colorama.Style.RESET_ALL
            print(f'{rsa_email} {color.join(records_email)}\n')  

    
    elif arguments.input and arguments.email == True:

        if not email(arguments.input):
            print(colorama.Fore.RED + 'Not found email address' + colorama.Style.RESET_ALL)
        else:
            found_email = email(args.input)
            for index in set(found_email):
                print(index)


    elif arguments.input and arguments.reg == True:
         if not reg(arguments.input):
             print(colorama.Fore.RED + 'Not found Windows registry' + colorama.Style.RESET_ALL)
         else:
             found_reg = reg(arguments.input)
             for index in set(found_reg):
                 print(index)
                           

    elif arguments.input and arguments.cve == True and arguments.report == True:
        conv = list(cve(arguments.input))
        return conv    
    
        
    elif arguments.input and arguments.cve == True:

        if not cve(arguments.input):
            print(colorama.Fore.RED + 'Not found CVEs' + colorama.Style.RESET_ALL)
        else:
            found_cves = cve(arguments.input)
            for index in set(found_cves):
                print(index)


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
            pdf.multi_cell(0, 10, f'- {query}')
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
    
    file_name = f"Relatório.pdf"
    pdf.output(file_name)
    print(f"Relatório gerado: {file_name}")


if option(args) == None:
    pass
else:
    cves_extraidas = option(args)
    cves_analyzed, cves_pending = check_analysis(cves_extraidas)
    generator_report(cves_analyzed, cves_pending)