import argparse

def arguments():
    
    parser = argparse.ArgumentParser(description='Tool for parsing IOCs on unstructured fonts like csv, txt, json, xml, files')      

    parser.add_argument('input', help='Full path of file to parser')
    parser.add_argument('--scnx','-scnx', action='store_true',help='This option select type output query to target siem securonix')
    parser.add_argument('--rsa','-rsa', action='store_true',help='This option select type output query to target siem RSA Netwitness')
    parser.add_argument('--md5','-md5', action='store_true',help='This option try to capture capture all hashes md5')
    parser.add_argument('--sha1', '-sha1', action='store_true',help='This option try to capture all hashes sha1')
    parser.add_argument('--sha256', '-sha256', action='store_true',help='This option try to capture all hashes sha256')
    parser.add_argument('--ip','-ip', action='store_true',help='This option try to capture all address ip')
    parser.add_argument('--domain', '-d', action='store_true', help='This option try to capture all domains address')
    parser.add_argument('--cve', '-cve', action='store_true', help='This option try capture CVEs IDs')
    parser.add_argument('--email', '-email', action='store_true', help='This option try capture all email addresses')
    parser.add_argument('--registry','-reg', action='store_true', help='This option try capture Windows registry')
    parser.add_argument('--artifact', '-art', action='store_true', help='This option try to capture all artifact like tools and process')
    parser.add_argument('--report', '-re', action='store_true', help='This option will generate report with public exploits analisys from public databases like ExploitDB and Packet Storm, only use with argument --cve EX: \watching_killer.py source.txt" --cve --report')
    parser.add_argument('--reputation', '-rep', action='store_true', help='This option verifies the reputation of address ip, necessary to use with argument -ip or --ip option EX: \watching_killer.py source.txt" --scnx -ip --reputation')
    parser.add_argument('--exploitdb', '-edb', action='store_true', help='This option verifies if the CVE has an exploit in the ExploitDB database, necessary to use with argument --cve EX: \watching_killer.py source.txt" --cve --exploitdb')
    parser.add_argument('-l', action='store_true', help='This option divides the results query in two parts EX: \watching_killer.py source.txt" --scnx --sha1 -l')
    parser.add_argument('-i', '--include', nargs='*', help='Add additional values separated by space to be included in the query only argument --artifact EX: python.exe .\watching_killer.py source.txt" --scnx -artifact -l -i cmd.exe malware.py')    
    

    return parser.parse_args()

if __name__ == "__main__":
    print('Error: This is not the main executable. Please execute python watching_killer.py -h or python watching_killer.py --help\n')
