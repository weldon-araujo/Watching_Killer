import colorama

def scnx_source_address():
    source_adress = colorama.Fore.BLUE + 'sourceaddress in' + colorama.Style.RESET_ALL
    return source_adress


def scnx_source_address_only(): 
    sourcec_address_only = colorama.Fore.BLUE + 'sourceaddress' + colorama.Style.RESET_ALL
    return sourcec_address_only


def scnx_stats():
    stats  = colorama.Fore.BLUE + '| STATS ' + colorama.Style.RESET_ALL
    return stats


def scnx_destination_adrress():
    dst_adrress = colorama.Fore.BLUE + 'destinationaddress in' + colorama.Style.RESET_ALL
    return dst_adrress


def scnx_destination_address_only():
    dst_address_only = colorama.Fore.BLUE + 'destinationaddress' + colorama.Style.RESET_ALL
    return dst_address_only


def scnx_old_file_hash():
    old_file_hash = colorama.Fore.BLUE + 'oldfilehash in' + colorama.Style.RESET_ALL
    return old_file_hash


def scnx_request_url():
    request_url = colorama.Fore.BLUE + 'requesturl in' + colorama.Style.RESET_ALL
    return request_url


def scnx_request_url_only():
    request_url_only = colorama.Fore.BLUE + 'requesturl' + colorama.Style.RESET_ALL
    return request_url_only


def scnx_email_recipient_domain():
    email_recipient_domain = colorama.Fore.BLUE + 'emailrecipientdomain in' + colorama.Style.RESET_ALL
    return email_recipient_domain


def scnx_email_recipient_domain_only():
    email_recipient_domain_only = colorama.Fore.BLUE + 'emailrecipientdomain' + colorama.Style.RESET_ALL
    return email_recipient_domain_only


def scnx_source_process_name():
    source_process_name = colorama.Fore.BLUE + 'sourceprocessname in' + colorama.Style.RESET_ALL
    return source_process_name


def scnx_source_process_name_only():
    scnx_source_processname_only = colorama.Fore.BLUE + 'sourceprocessname' + colorama.Style.RESET_ALL
    return scnx_source_processname_only


def scnx_destination_process_name():
    destination_process_name = colorama.Fore.BLUE + 'destinationprocessname in' + colorama.Style.RESET_ALL
    return destination_process_name


def scnx_destination_process_name_only():
    destination_process_name_only = colorama.Fore.BLUE + 'destinationprocessname' + colorama.Style.RESET_ALL
    return destination_process_name_only


def scnx_mailboxownerupn():
    mailboxownerupn = colorama.Fore.BLUE + 'mailboxownerupn in' + colorama.Style.RESET_ALL
    return mailboxownerupn


def scnx_mailboxownerupn_without():
    mailboxownerupn = colorama.Fore.BLUE + 'mailboxownerupn' + colorama.Style.RESET_ALL
    return mailboxownerupn


def scnx_accountname():
    accountname = colorama.Fore.BLUE + 'accountname in' + colorama.Style.RESET_ALL
    return accountname


def scnx_accountname_without():
    accountname = colorama.Fore.BLUE + 'accountname' + colorama.Style.RESET_ALL
    return accountname


def scnx_workemail():
    workemail = colorama.Fore.BLUE + 'workemail in' + colorama.Style.RESET_ALL
    return workemail


def scnx_workemail_without():
    workemail = colorama.Fore.BLUE + 'workemail' + colorama.Style.RESET_ALL
    return workemail


def scnx_command_line():
    command_line = colorama.Fore.BLUE + 'commandline in' + colorama.Style.RESET_ALL
    return command_line


def scnx_command_line_only():
    scnx_command_line_only = colorama.Fore.BLUE + 'commandline' + colorama.Style.RESET_ALL 
    return scnx_command_line_only


def rsa_email():
    email = colorama.Fore.BLUE + 'email =' + colorama.Style.RESET_ALL
    return email


def scnx_file_name():
    file_name = colorama.Fore.BLUE + 'filename in' + colorama.Style.RESET_ALL
    return file_name


def scnx_file_name_only():
    file_name_only = colorama.Fore.BLUE + 'filename' + colorama.Style.RESET_ALL
    return file_name_only


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


def rsa_process_only():
    process = colorama.Fore.BLUE + 'process =' + colorama.Style.RESET_ALL
    return process


def process_contains():
    process_contains = colorama.Fore.BLUE + 'process contains' + colorama.Style.RESET_ALL
    return process_contains


def rsa_src_process():
    src_process = colorama.Fore.BLUE + 'process.src =' + colorama.Style.RESET_ALL
    return src_process