import colorama

def scnx_eventdata_only():
    eventdata = colorama.Fore.BLUE + 'eventdata' + colorama.Style.RESET_ALL
    return eventdata


def scnx_status():
    status = colorama.Fore.BLUE + 'status in' + colorama.Style.RESET_ALL    
    return status


def scnx_status_only():
    status_only = colorama.Fore.BLUE + 'status' + colorama.Style.RESET_ALL
    return status_only


def scnx_host():
    host = colorama.Fore.BLUE + 'host in' + colorama.Style.RESET_ALL
    return host


def scnx_host_only():
    host_only = colorama.Fore.BLUE + 'host' + colorama.Style.RESET_ALL
    return host_only


def scnx_uri():
    uri = colorama.Fore.BLUE + 'uri in' + colorama.Style.RESET_ALL
    return uri


def scnx_uri_only():
    uri_only = colorama.Fore.BLUE + 'uri' + colorama.Style.RESET_ALL
    return uri_only


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


def scnx_old_file_hash_only():
    old_file_hash_only = colorama.Fore.BLUE + 'oldfilehash' + colorama.Style.RESET_ALL
    return old_file_hash_only 


def scnx_file_hash():
    file_hash = colorama.Fore.BLUE + 'filehash in' + colorama.Style.RESET_ALL
    return file_hash


def scnx_file_hash_only():
    file_hash_only = colorama.Fore.BLUE + 'filehash' + colorama.Style.RESET_ALL
    return file_hash_only


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


def scnx_email_recipient():
    email_recipient = colorama.Fore.BLUE + 'emailrecipient in' + colorama.Style.RESET_ALL
    return email_recipient


def scnx_email_recipient_only():
    email_recipient_only = colorama.Fore.BLUE + 'emailrecipient' + colorama.Style.RESET_ALL
    return email_recipient_only


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


def scnx_fqdn():
    scnx_fqdn = colorama.Fore.BLUE + 'fqdn in' + colorama.Style.RESET_ALL
    return scnx_fqdn


def scnx_fqdn_only():
    scnx_fqdn_only = colorama.Fore.BLUE + 'fqdn' + colorama.Style.RESET_ALL
    return scnx_fqdn_only


def scnx_root_domain():
    scnx_root_domain = colorama.Fore.BLUE + 'rootdomain in' + colorama.Style.RESET_ALL
    return scnx_root_domain


def scnx_root_domain_only():
    scnx_root_domain_only = colorama.Fore.BLUE + 'rootdomain' + colorama.Style.RESET_ALL
    return scnx_root_domain_only


def rsa_email():
    email = colorama.Fore.BLUE + 'email =' + colorama.Style.RESET_ALL
    return email


def scnx_file_name():
    file_name = colorama.Fore.BLUE + 'filename in' + colorama.Style.RESET_ALL
    return file_name


def scnx_original_file_name():
    original_file_name = colorama.Fore.BLUE + 'originalfilename in' + colorama.Style.RESET_ALL
    return original_file_name


def scnx_original_file_name_only():
    original_file_name_only = colorama.Fore.BLUE + 'originalfilename' + colorama.Style.RESET_ALL
    return original_file_name_only


def childprocesscommandline():
    childprocesscommandline = colorama.Fore.BLUE + 'childprocesscommandline in' + colorama.Style.RESET_ALL   
    return childprocesscommandline


def childprocesscommandline_only():
    childprocesscommandline_only = colorama.Fore.BLUE + 'childprocesscommandline' + colorama.Style.RESET_ALL
    return childprocesscommandline_only


def scnx_file_name_only():
    file_name_only = colorama.Fore.BLUE + 'filename' + colorama.Style.RESET_ALL
    return file_name_only


def scnx_object_file():
    object_file = colorama.Fore.BLUE + 'objectfile in' + colorama.Style.RESET_ALL
    return object_file


def scnx_object_file_only():
    object_file_only = colorama.Fore.BLUE + 'objectfile' + colorama.Style.RESET_ALL
    return object_file_only


def scnx_baseeventid():
    baseeventid = colorama.Fore.BLUE + 'baseeventid in' + colorama.Style.RESET_ALL
    return baseeventid


def scnx_childprocesscommandline():
    childprocesscommandline = colorama.Fore.BLUE + 'childprocesscommandline in' + colorama.Style.RESET_ALL
    return childprocesscommandline

def scnx_childprocesscommandline_only():
    childprocesscommandline_only = colorama.Fore.BLUE + 'childprocesscommandline' + colorama.Style.RESET_ALL
    return childprocesscommandline_only

def scnx_scriptpath():
    scriptpath = colorama.Fore.BLUE + 'scriptpath in' + colorama.Style.RESET_ALL
    return scriptpath

def scnx_scriptpath_only():
    scriptpath_only = colorama.Fore.BLUE + 'scriptpath' + colorama.Style.RESET_ALL
    return scriptpath_only

def scnx_file_path():
    filepath = colorama.Fore.BLUE + 'filepath in' + colorama.Style.RESET_ALL
    return filepath

def scnx_file_path_only():
    filepath_only = colorama.Fore.BLUE + 'filepath' + colorama.Style.RESET_ALL
    return filepath_only

def scnx_md5hash():
    md5hash = colorama.Fore.BLUE + 'md5hash in' + colorama.Style.RESET_ALL
    return md5hash

def rsa_object_name():
    object_name = colorama.Fore.BLUE + 'object.name =' + colorama.Style.RESET_ALL
    return object_name


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


if __name__ == "__main__":
    print('Error: This is not the main executable. Please execute python watching_killer.py -h or python watching_killer.py --help\n')