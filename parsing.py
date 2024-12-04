import argparse

def arguments():
    
    parser = argparse.ArgumentParser(description='Tool for parsing IOCs')

    parser.add_argument('input', help='Path of file to parser')
    parser.add_argument('--scnx','-scnx', action='store_true',help='This option select type output query to target siem securonix')
    parser.add_argument('--rsa','-rsa', action='store_true',help='This option select type output query to target siem RSA Netwitness')
    parser.add_argument('--md5','-md5', action='store_true',help='This option try to capture capture all hashes md5')
    parser.add_argument('--sha1', '-sha1', action='store_true',help='This option try to capture all hashes sha1')
    parser.add_argument('--sha256', '-sha256', action='store_true',help='This option try to capture all hashes sha256')
    parser.add_argument('--ip','-ip', action='store_true',help='This option try to capture all address ip')
    parser.add_argument('--domain', '-domain', action='store_true', help='This option try to capture all domains address')
    parser.add_argument('--artifact', '-artifact', action='store_true', help='This option try to capture all artifact like tools and process')
    parser.add_argument('--reputation', '-reputation', action='store_true', help='This option verifies the reputation of address ip, necessary to use with -ip or --ip option')
    parser.add_argument('--email', '-email', action='store_true', help='This option try capture all email addresses')
    parser.add_argument('--cve', '-cve', action='store_true', help='This option try capture CVEs IDs')
    parser.add_argument('--reg','-r', action='store_true', help='This option try capture Windows registry')
    parser.add_argument('-l', action='store_true', help='This option divides the results query in two parts')

    return parser.parse_args()

if __name__ == "__main__":
    print('Error, this not main executable, please execute python watching_killer.py -h or --help')
