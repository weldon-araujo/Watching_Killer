import argparse

def arguments():
    
    parser = argparse.ArgumentParser(description='Tool for parsing of IOCs')

    parser.add_argument('input', help='Path of file to parser')
    parser.add_argument('--scnx', action='store_true',help='output query to target siem securonix')
    parser.add_argument('--rsa', action='store_true',help='output query to target siem rsa')
    parser.add_argument('--md5', action='store_true',help='try to capture capture all hashes md5')
    parser.add_argument('--sha1', action='store_true',help='try to capture all hashes sha1')
    parser.add_argument('--sha256', action='store_true',help='try to capture all hashes sha256')
    parser.add_argument('--ip', action='store_true',help='try to capture all hashes address ip')
    parser.add_argument('--domain', action='store_true', help='try to capture all hashes domains')
    parser.add_argument('--artifact', action='store_true', help='try to capture all artifact like process')
    parser.add_argument('--reputation', action='store_true', help='verify reputataion of address ip')
    parser.add_argument('--all', action='store_true', help='This option runl all option')

    return parser.parse_args()

if __name__ == "__main__":
    print('Error, this not main executable, please execute IOC.py')
