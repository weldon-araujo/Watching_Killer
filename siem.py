import colorama

def scnx_src_address():
    src_adress = colorama.Fore.BLUE + 'sourceaddress in' + colorama.Style.RESET_ALL
    return src_adress


def scnx_src_address_only():
    src_address_only = colorama.Fore.BLUE + 'sourceaddress =' + colorama.Style.RESET_ALL
    return src_address_only


def scnx_destination_adrress():
    dst_adrress = colorama.Fore.BLUE + 'destinationaddress in' + colorama.Style.RESET_ALL
    return dst_adrress


def scnx_destination_address_only():
    dst_address_only = colorama.Fore.BLUE + 'destinationaddress =' + colorama.Style.RESET_ALL
    return dst_address_only


def scnx_old_file_hash():
    old_file_hash = colorama.Fore.BLUE + 'oldfilehash in' + colorama.Style.RESET_ALL
    return old_file_hash


def scnx_request_url():
    request_url = colorama.Fore.BLUE + 'requesturl' + colorama.Style.RESET_ALL
    return request_url


def scnx_processinformationprocessname():
    processinformationprocessname = colorama.Fore.BLUE + 'processinformationprocessname' + colorama.Style.RESET_ALL
    return processinformationprocessname


def rsa_source_address():
    source_address = colorama.Fore.BLUE + 'ip.src =' + colorama.Style.RESET_ALL
    return source_address


def rsa_destination_adress():
    destination_address = colorama.Fore.BLUE + 'ip.dst =' + colorama.Style.RESET_ALL
    return destination_address


def rsa_cheksum():
    checksum = colorama.Fore.BLUE + 'checksum =' + colorama.Style.RESET_ALL
    return checksum    


def rsa_url():
    url = colorama.Fore.BLUE + 'url =' + colorama.Style.RESET_ALL
    return url


def rsa_process():
    process = colorama.Fore.BLUE + 'process =' + colorama.Style.RESET_ALL
    return process


def rsa_src_process():
    src_process = colorama.Fore.BLUE + 'process.src =' + colorama.Style.RESET_ALL
    return src_process