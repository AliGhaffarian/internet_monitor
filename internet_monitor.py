from datetime import time
import requests
import yaml
import logging
import socket
import os
import time
import errno
import argparse
import urllib3

urllib3.disable_warnings()

logger = logging.getLogger()
logger.setLevel(logging.INFO)

stdout_handler = logging.StreamHandler()
stdout_handler.setFormatter(
        logging.Formatter('%(asctime)s [%(levelname)s] %(name)s [%(funcName)s]: %(message)s')
        )
logger.addHandler(stdout_handler)

SIMPLE_REPR_DELIM="\t"
SIMPLE_REPR_HEADER=f"server{SIMPLE_REPR_DELIM}\
average_delay{SIMPLE_REPR_DELIM}\
longest_delay{SIMPLE_REPR_DELIM}\
shortest_delay{SIMPLE_REPR_DELIM}\
failed_ping_count"
PROTOCOL_NOT_SUPPORTED_STR="protocol not supported"
CONF_FILE="servers.yaml"
check_intervals=1
default_protocol_confs = {
        "timeout": 1,
        "count" : 4,
        "retries" : 2
        }

socket.setdefaulttimeout(
        default_protocol_confs['timeout']
        )
supported_protocols=["http", "https", "tcp"]

config_from_file={} #to be parsed in parse_config()
"""
[{
    protocol : {
        servers: [str],
        timeout: int,
        count  : int,
        retries: int
    }
}]
"""

BLACK_LIST_IPS = ["10.10.34.34", "10.10.34.35", "10.10.34.36"]

def clear_screen():
    # For Windows
    if os.name == 'nt':
        _ = os.system('cls')
    # For macOS and Linux
    else:
        _ = os.system('clear')


def resolve_domain_name(domain : str):
    result = socket.gethostbyname(domain)
    if result in BLACK_LIST_IPS:
        raise socket.gaierror(f"{domain} resolved to blacklist ip {result}")
    return result
    
def fill_missing_protocol_conf(conf : dict):
    for protocol_conf in default_protocol_confs:
        if protocol_conf not in conf:
            conf.update(
                    {protocol_conf: default_protocol_confs[protocol_conf]}
                    )


def parse_config(filename = CONF_FILE)->dict:
    global config_from_file
    read_buff = open(filename).read()
    parsed_yaml_file = yaml.safe_load(read_buff)

    logger.debug(f"parsed yaml from {filename=} : {parsed_yaml_file}")
    
    for key in parsed_yaml_file:
        fill_missing_protocol_conf(parsed_yaml_file[key])

    
    config_from_file = parsed_yaml_file
    return config_from_file


def _check_http_or_https(protocol : str, 
                         host : str, 
                         timeout : int = default_protocol_confs["timeout"], 
                         count : int = default_protocol_confs["count"],
                         retries : int = default_protocol_confs["retries"]
                         )->dict:
    """
    return:
    {
        server: str,
        longest_delay : int,
        shortest_delay : int,
        failed_ping_count : int,
        causes_of_failures : [Exception],
        average_delay : int
    }
    """
    result = {}

    retries = requests.adapters.Retry(total=retries,
                backoff_factor=0,
                status_forcelist=[ None ])

    host_ip_address = ""
    try:
        host_ip_address = resolve_domain_name(host)
    except socket.gaierror:
        count = 0

    url = f"{protocol}://{host_ip_address}"

    session = requests.Session()
    session.mount(
            f"{protocol}://",
            requests.adapters.HTTPAdapter(max_retries=retries)
            )

    success_count = 0
    total_delay : int = 0
    shortest_delay = -1
    longest_delay = -1
    causes_of_failures : [Exception] = []

    if len(host_ip_address) == 0:
        causes_of_failures.append("Failed to resolve")
        success_count = -1 # so the result['failed_ping_count'] = 1 assuming count is 0
        
    for _ in range(count):
        try:
            resp = session.head(url, timeout=timeout, verify=False)
            if not resp.ok:
                #warn
                pass
            success_count += 1

            current_delay =resp.elapsed.microseconds // 1000 # to milliseconds
            total_delay += current_delay
            
            if success_count == 1:
                shortest_delay = current_delay
                longest_delay = current_delay

            if current_delay > longest_delay:
                longest_delay = current_delay
            if current_delay < shortest_delay:
                shortest_delay = current_delay
        except requests.exceptions.ConnectionError as e:
            causes_of_failures.append(e)
            
    result.update({"server"            : host})
    result.update({"shortest_delay"    : shortest_delay})
    result.update({"longest_delay"     : longest_delay})
    result.update({"failed_ping_count" : count - success_count})
    result.update({"average_delay"     : 
                   total_delay / success_count if success_count else -1})
    result.update({"causes_of_failures": causes_of_failures})

    return result

def check_http(host : str, 
               timeout : int = default_protocol_confs["timeout"], 
               count : int = default_protocol_confs["count"],
               retries : int = default_protocol_confs["retries"]
               )->dict:
    return _check_http_or_https("http", host, timeout, count, retries)


def check_https(host : str, 
               timeout : int = default_protocol_confs["timeout"], 
               count : int = default_protocol_confs["count"],
               retries : int = default_protocol_confs["retries"]
               )->dict:
    return _check_http_or_https("https", host, timeout, count, retries)

def check_tcp(host : str, 
               timeout : int = default_protocol_confs["timeout"], 
               count : int = default_protocol_confs["count"],
               retries : int = default_protocol_confs["retries"]
               )->dict:
    """
    return:
    {
        server: str,
        longest_delay : int,
        shortest_delay : int,
        failed_ping_count : int,
        causes_of_failures : [Exception],
        average_delay : int
    }
    TODO: implement retry
    """
    result = {}
    
    port = host.split(':')[1]
    host_ip_address = ""
    try:
        host_ip_address = resolve_domain_name(host.split(':')[0])
    except socket.gaierror:
        count = 0

    success_count = 0
    total_delay : int = 0
    shortest_delay = -1
    longest_delay = -1
    causes_of_failures : [Exception] = []

    if len(host_ip_address) == 0:
        causes_of_failures.append("Failed to resolve")
        success_count = -1 # so the result['failed_ping_count'] = 1 assuming count is 0
        
    for i in range(count):
       
        # New Socket
        s = socket.socket(
        socket.AF_INET, socket.SOCK_STREAM)

        s.settimeout(timeout)

        start = time.time()
        # Try to Connect
        try:
            s.connect((host_ip_address, int(port)))
            s.shutdown(socket.SHUT_RD)

            # Stop Timer
            stop = time.time()
            current_delay = int((stop - start) * 1000) # to milliseconds

            success_count += 1
            total_delay += current_delay
            
            if success_count == 1:
                shortest_delay = current_delay
                longest_delay = current_delay

            if current_delay > longest_delay:
                longest_delay = current_delay
            if current_delay < shortest_delay:
                shortest_delay = current_delay

        
        # Connection Timed Out
        except socket.timeout as e:
            causes_of_failures.append(e)
        except OSError as e:
            causes_of_failures.append(e)

            
    result.update({"server"            : host})
    result.update({"shortest_delay"    : shortest_delay})
    result.update({"longest_delay"     : longest_delay})
    result.update({"failed_ping_count" : count - success_count})
    result.update({"average_delay"     : 
                   total_delay / success_count if success_count else -1})
    result.update({"causes_of_failures": causes_of_failures})

    return result







def repr_detailed_server_status(status : dict, print_func=print):
    """
    status:
    {
        server: str,
        longest_delay : int,
        shortest_delay : int,
        failed_ping_count : int,
        causes_of_failures : [Exception],
        average_delay : int
    }
    """
    print_func(f"server : {status['server']}") 
    print_func(f"average_delay : {status['average_delay']} ms")
    print_func(f"shortest_delay : {status['shortest_delay']} ms")
    print_func(f"longest_delay : {status['longest_delay']} ms")

    if status['failed_ping_count']:
        print_func(f"failed_ping_count : {status['failed_ping_count']}")
        for cause in status['causes_of_failures']:
            print_func(f"\t{cause}")
    print("--------")

def repr_simple_server_status(status : dict, print_func = print):
    """
    status:
    {
        server: str,
        longest_delay : int,
        shortest_delay : int,
        failed_ping_count : int,
        causes_of_failures : [Exception],
        average_delay : int
    }

    simple server status header:
    """
    logger.debug(f"{status}")
    print_str = f"{status['server']}{SIMPLE_REPR_DELIM}\
{status['average_delay']}{SIMPLE_REPR_DELIM}\
{status['longest_delay']}{SIMPLE_REPR_DELIM}\
{status['shortest_delay']}{SIMPLE_REPR_DELIM}\
{status['failed_ping_count']}"

    print_func(print_str)
 


def check_status(protocols_to_check=supported_protocols, conf=None)->dict:
    """
    return:
    {
        protocol_name:
            [{
                server: str
                longest_delay : int, 
                shortest_delay: int, 
                failed_ping_count: int,
                causes_of_failures : [Exception]
                average_delay: int
            }]
    }
    """
    global config_from_file
    if conf is None:
        conf = config_from_file

    result = {}
    for protocol in protocols_to_check:
        logger.debug(f"checking protocol {protocol}")
        if protocol not in supported_protocols:
            result.update({protocol : PROTOCOL_NOT_SUPPORTED_STR})
            continue
                
        if protocol not in result:
            result.update({protocol : []})


        for server in conf[protocol]["servers"]:
            check_func = compile(
                    f"check_{protocol}('{server}', {conf[protocol]['timeout']})",
                    'None',"eval")

            test_result = eval(check_func)
            result[protocol].append(test_result)

    return result


def repr_status(status, mode = "simple")->None:
    valid_modes = ["simple", "detailed"]
    if mode not in valid_modes:
        raise Exception(errno.EINVAL, os.strerror(errno.EINVAL))

    repr_func = repr_detailed_server_status if mode == "detailed" else repr_simple_server_status
    if mode == "simple":
        print(SIMPLE_REPR_HEADER, end="\n\n")

    for protocol in status:
        print(protocol)

        if status[protocol] == PROTOCOL_NOT_SUPPORTED_STR:
            print(PROTOCOL_NOT_SUPPORTED_STR, end="\n\n")
            continue

        for server_status in status[protocol]:
            repr_func(server_status)

        print("\n")


def handle_args():
    parser = argparse.ArgumentParser(
            description="simple network monitoring script"
            )

    parser.add_argument(
            "--detailed", 
            help="use detailed representation of status",
            action="store_true"
            )

                
    parser.parse_args()

    return parser.parse_args()
        


if __name__ == "__main__":
    args = handle_args()
    parse_config()
    while True:
        status = check_status(config_from_file.keys())

        if not (logger.level < logging.DEBUG):
            clear_screen()
        repr_mode = "simple" if not args.detailed else "detailed"
        repr_status(status, repr_mode)
        time.sleep(check_intervals)

