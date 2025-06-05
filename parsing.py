import argparse
import sys
from colorama import Fore, Style, init

init(autoreset=True)

def print_custom_help():
    print(f"""{Fore.CYAN}{Style.BRIGHT}
Usage:
  python watching_killer.py [options] <input_file>

{Fore.YELLOW}Description:{Style.RESET_ALL}
  {Fore.WHITE}A command-line toolkit designed to parse and analyze threat intelligence data from unstructured sources
  such as .txt, .csv, .json, and .xml files. It supports extraction of multiple artifacts including domains, IPs,
  hashes, registry keys, file paths, CVEs, and Base64 strings.{Style.RESET_ALL}

{Fore.YELLOW}Positional Argument:{Style.RESET_ALL}
  {Fore.GREEN}input{Style.RESET_ALL}                Full path of file to parse

{Fore.YELLOW}General Options:{Style.RESET_ALL}
  {Fore.GREEN}-h, --help{Style.RESET_ALL}           Show this help message and exit
  
{Fore.YELLOW}Hash Extraction:{Style.RESET_ALL}
  {Fore.GREEN}--md5{Style.RESET_ALL}                Extract MD5 hashes
  {Fore.GREEN}--sha1{Style.RESET_ALL}               Extract SHA1 hashes
  {Fore.GREEN}--sha256{Style.RESET_ALL}             Extract SHA256 hashes

{Fore.YELLOW}Artifact Extraction:{Style.RESET_ALL}
  {Fore.GREEN}--artifact, -art{Style.RESET_ALL}     Extract tools/processes
  {Fore.GREEN}--dll, -dll{Style.RESET_ALL}          Extract DLLs (use with -scnx or -rsa)
  {Fore.GREEN}--ps1, -ps1{Style.RESET_ALL}          Extract PowerShell scripts (use with -scnx or -rsa)
  {Fore.GREEN}--exe, -exe{Style.RESET_ALL}          Extract executables (use with -scnx or -rsa)

{Fore.YELLOW}Other Extraction:{Style.RESET_ALL}
  {Fore.GREEN}--ip, -ip{Style.RESET_ALL}            Extract IP addresses
  {Fore.GREEN}--domain, -d{Style.RESET_ALL}         Extract domain names
  {Fore.GREEN}--email, -email{Style.RESET_ALL}      Extract email addresses
  {Fore.GREEN}--registry, -reg{Style.RESET_ALL}     Extract Windows Registry keys

{Fore.YELLOW}CVE Options:{Style.RESET_ALL}
  {Fore.GREEN}--cve, -cve{Style.RESET_ALL}          Extract CVE IDs
  {Fore.GREEN}--cve_details, -cved{Style.RESET_ALL} Include CVSS scores and references
  {Fore.GREEN}--cvereport, -cver{Style.RESET_ALL}   Generate CVE reports with public exploit analysis
  {Fore.GREEN}--exploitdb, -edb{Style.RESET_ALL}    Check ExploitDB for matching CVEs
  {Fore.GREEN}--github, -gh{Style.RESET_ALL}        Search GitHub for public exploits (requires --cve)

{Fore.YELLOW}SIEM Output Options:{Style.RESET_ALL}
  {Fore.GREEN}--securonix, -scnx{Style.RESET_ALL}   Output query format for Securonix
  {Fore.GREEN}--rsa, -rsa{Style.RESET_ALL}          Output query format for RSA NetWitness

{Fore.YELLOW}enrichment and auxiliaries:{Style.RESET_ALL}
  {Fore.GREEN}-i, --include{Style.RESET_ALL}        Include custom values in --artifact query
  {Fore.GREEN}--remove, -r{Style.RESET_ALL}         Remove specific values from query
  {Fore.GREEN}--reputation, -rep{Style.RESET_ALL}   Check IP reputation (requires --ip)
  {Fore.GREEN}-l{Style.RESET_ALL}                   Divide query output into two parts

{Fore.CYAN}Examples:{Style.RESET_ALL}
  python watching_killer.py source.txt --cve --cvereport
  python watching_killer.py source.json --artifact -r powershell.exe cmd.exe
  python watching_killer.py source.xml -scnx --artifact -i wscript.exe regsvr32.exe
""")

def arguments():
    if '-h' in sys.argv or '--help' in sys.argv:
        print_custom_help()
        sys.exit(0)

    parser = argparse.ArgumentParser(add_help=False)

    parser.add_argument('input', help='Full path of file to parser')
    parser.add_argument('--securonix','-scnx', action='store_true', help='Output query format for Securonix')
    parser.add_argument('--rsa','-rsa', action='store_true', help='Output query format for RSA NetWitness')
    parser.add_argument('--md5','-md5', action='store_true', help='Extract MD5 hashes')
    parser.add_argument('--sha1','-sha1', action='store_true', help='Extract SHA1 hashes')
    parser.add_argument('--sha256','-sha256', action='store_true', help='Extract SHA256 hashes')
    parser.add_argument('--ip','-ip', action='store_true', help='Extract IP addresses')
    parser.add_argument('--domain','-d', action='store_true', help='Extract domain names')
    parser.add_argument('--cve','-cve', action='store_true', help='Extract CVE IDs')
    parser.add_argument('--cve_details','-cved', action='store_true', help='Include CVSS scores and references for CVEs')
    parser.add_argument('--email','-email', action='store_true', help='Extract email addresses')
    parser.add_argument('--registry','-reg', action='store_true', help='Extract Windows registry keys')
    parser.add_argument('--artifact','-art', action='store_true', help='Extract artifacts such as tools and processes')
    parser.add_argument('--dll','-dll', action='store_true', help='Extract DLLs (use with -scnx or -rsa)')
    parser.add_argument('--ps1','-ps1', action='store_true', help='Extract PowerShell scripts (use with -scnx or -rsa)')
    parser.add_argument('--exe','-exe', action='store_true', help='Extract executables (use with -scnx or -rsa)')
    parser.add_argument('--cvereport','-cver', action='store_true', help='Generate CVE reports using public databases (use with --cve)')
    parser.add_argument('--reputation','-rep', action='store_true', help='Check reputation of IPs (requires --ip)')
    parser.add_argument('--exploitdb','-edb', action='store_true', help='Check ExploitDB for CVEs (requires --cve)')
    parser.add_argument('--github','-gh', action='store_true', help='Search GitHub for public exploits (requires --cve)')
    parser.add_argument('-l', action='store_true', help='Divide query output into two parts')
    parser.add_argument('-i','--include', nargs='*', help='Include custom values in --artifact query')
    parser.add_argument('--remove','-r', nargs='*', help='Remove specific values from query output')

    return parser.parse_args()

if __name__ == "__main__":
    print(f"{Fore.RED}Error:{Style.RESET_ALL} This is not the main executable. Please run:")
    print(f"{Fore.YELLOW}python watching_killer.py --help\n")
