import re
import requests
import csv
import json
import os
from dotenv import load_dotenv
import parsing
import siem
import colorama

load_dotenv(override=True)

abuseip = os.getenv("abuseipdbkey")

args = parsing.arguments()

# Function to parsing in file input

def ip(arq):
    ips = []
    with open(arq, 'r', encoding="utf8") as outfile:
        reader = csv.reader(outfile)
        for raw in reader:
            for cell in raw:
                cell = cell.replace('[', '').replace(']', '')
                matches = re.findall(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', cell)
                ips.extend(matches)

    return set(ips) 


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
    tld = ['.com','net','.br','.onion','org','gov', '.de', '.at']
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
    process_extension = ['.exe','dll','.py','.vbs','.ps1','.bin','.bat']
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


# Main arguments test for run


def option(arguments):
    
    if arguments.input and arguments.ip == True and arguments.scnx == True:
        if not ip(arguments.input):
            print('not found ip address')
        else:
            records_ip = []
            scnx_src_address = siem.scnx_src_address()
            scnx_dst_address = siem.scnx_destination_adrress()
            src_without = siem.scnx_src_address_without()
            dst_without = siem.scnx_destination_address_without()
            stats = siem.scnx_stats()
            found_ip = ip(args.input)
            
            for index in found_ip:
                records_ip.append(index)

            print('[AVs / EDRs / SOs]:\n')

            print(f'{scnx_src_address} ({', '.join(records_ip)})\n')

            print(f'{scnx_dst_address} ({', '.join(records_ip)})\n')

            print(f'{scnx_src_address} ({', '.join(records_ip)}) {colorama.Fore.BLUE}OR{colorama.Style.RESET_ALL} {scnx_dst_address} ({', '.join(records_ip)})\n')
                    
            print(f'{scnx_src_address} ({', '.join(records_ip)}) {colorama.Fore.BLUE}OR{colorama.Style.RESET_ALL} {scnx_dst_address} ({', '.join(records_ip)}) {stats} {src_without}\n')  

            print(f'{scnx_src_address} ({', '.join(records_ip)}) {colorama.Fore.BLUE}OR{colorama.Style.RESET_ALL} {scnx_dst_address} ({', '.join(records_ip)}) {stats} {dst_without}\n')
                 
            
    elif arguments.input and arguments.ip == True and arguments.rsa == True:

        if not ip(arguments.input):
            print('not found ip address')
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
            print(f'{rsa_src_adress} {color.join(records_ip)} {colorama.Fore.BLUE} OR {colorama.Style.RESET_ALL}')

            color = ' || ' + colorama.Fore.BLUE + ' ip.dst = ' + colorama.Style.RESET_ALL
            print(rsa_dst_adress, color.join(records_ip))
        

    elif arguments.input and arguments.ip == True and arguments.reputation == True:

        if not ip(arguments.input):
            print('not found ip address')
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
            print('not found ip address')
        else:        
            found_ip = ip(args.input)
            for index in set(found_ip):
                print(index)


    elif arguments.input and arguments.domain == True and arguments.scnx == True:

        if not domain(arguments.input):
            print('not found domain')
        else:
            records_domain = []
            scnx_request_url = siem.scnx_request_url()
            scnx_request_without = siem.scnx_request_url_without()
            stats = siem.scnx_stats()
            found_domain = domain(args.input)

            for index in found_domain:
                records_domain.append(index)

            print('[NGFW / WAF / PROXY]:\n')
            print(f'{scnx_request_url} ({', '.join(records_domain)})\n')
            print(f'{scnx_request_url} ({', '.join(records_domain)}) {stats} {scnx_request_without}')

    
    elif arguments.input and arguments.domain == True and arguments.rsa == True:

        if not domain(arguments.input):
            print('not found doman address')
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
            print('not found domain address')
        else:        
            found_domain = domain(args.input)
            for index in set(found_domain):
                print(index)
        
    
    elif arguments.input and arguments.artifact == True and arguments.scnx == True:

        if not artifact(arguments.input):
            print('not found artifact')
        else:        
            records_artifact = []
            scnx_processinformationprocessname = siem.scnx_processinformationprocessname()
            found_artifact = artifact(args.input)
            for index in found_artifact:
                records_artifact.append(index)
            print('[AVS / EDRS / Windows / Linux]:\n')
            print(f'{scnx_processinformationprocessname} ({', '.join(records_artifact)})')

    elif arguments.input and arguments.artifact == True and arguments.rsa == True:

        if not artifact(arguments.input):
            print('not found artifact')
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
            print('not found artifact')
        else:
            found_artifact = artifact(args.input)
            for index in set(found_artifact):
                print(index)


    elif arguments.input and arguments.md5 == True and arguments.scnx == True:

        if not md5(arguments.input):
            print('not found md5 hashes')
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
            print('not found md5 hashes')
        else:        
            records_md5 = []
            rsa_checksum = siem.rsa_cheksum()
            found_checksum = md5(args.input)

            for index in found_checksum:
                records_md5.append(index)

            print('[AVs / EDRs]:\n')
            color = ' ||' + colorama.Fore.BLUE + ' checksum = ' + colorama.Style.RESET_ALL
            print(f'{rsa_checksum} {color.join(records_md5)} \n') 

            print('[Sysmon]\n')
            color = ' ||' + colorama.Fore.BLUE + ' checksum = ' + colorama.Style.RESET_ALL + "'md5="
            records_md5 = [f"{md5}'" for md5 in records_md5]        
            print(f"{rsa_checksum} 'md5={color.join(records_md5)}")
                        
           
 
    elif arguments.input and arguments.md5 == True:

        if not md5(arguments.input):
            print('not found md5 hashes')
        else:        
            found_md5 = md5(args.input)
            for index in set(found_md5):
                print(index)

    
    elif arguments.input and arguments.sha1 == True and arguments.scnx == True:

        if not sha1(arguments.input):
            print('not found sha1 hashes')
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
            print('not found sha1 hashes')
        else:        
            records_sha1 = []
            rsa_checksum = siem.rsa_cheksum()
            found_checksum = sha1(args.input)

            for index in found_checksum:
                records_sha1.append(index)
            print('[AVs / EDRs]:\n')
            
            color = ' || ' + colorama.Fore.BLUE + ' checksum = ' + colorama.Style.RESET_ALL
            print(f'{rsa_checksum} {color.join(records_sha1)}\n')  
            print('[Sysmon]\n')

            color = ' ||' + colorama.Fore.BLUE + ' checksum = ' + colorama.Style.RESET_ALL + "'sha1="
            records_sha1 = [f"{sha1}'" for sha1 in records_sha1]
            print(f"{rsa_checksum} 'sha1={color.join(records_sha1)}") 


    elif arguments.input and arguments.sha1 == True:

        if not sha1(arguments.input):
            print('not found sha1 hashes')
        else:        
            found_sha1 = sha1(args.input)
            for index in set(found_sha1):
                print(index)

    
    elif arguments.input and arguments.sha256 == True and arguments.scnx == True:

        if not sha256(arguments.input):
            print('not found sha256 hashes')
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
            print('not found sha256 hashes')
        else:
            records_sha256 = []
            rsa_checksum = siem.rsa_cheksum()
            found_checksum = sha256(args.input)

            for index in found_checksum:
                records_sha256.append(index)

            print('[AVs / EDRs]:\n')
            color = ' || ' + colorama.Fore.BLUE + ' checksum = ' + colorama.Style.RESET_ALL
            print(f'{rsa_checksum} {color.join(records_sha256)}\n')  

            print('[Sysmon]\n')
            color = ' ||' + colorama.Fore.BLUE + ' checksum = ' + colorama.Style.RESET_ALL + "'sha256="
            records_sha256 = [f"{sha256}'" for sha256 in records_sha256]
            print(f"{rsa_checksum} 'sha256={color.join(records_sha256)}") 
        

    elif arguments.input and arguments.sha256 == True:

        if not sha256(arguments.input):
            print('not found sha256 hashes')
        else:
            found_sha256 = sha256(args.input)
            for index in set(found_sha256):
                print(index)


option(args)