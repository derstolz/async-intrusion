#!/usr/bin/env python3

import random
import string
from subprocess import call as run
from threading import Thread
from time import sleep

import requests

THREAD_POOL_EXHAUSTED_LIMIT = 10
SLEEP_TIMER_IN_SECONDS = 1
DEFAULT_SLEEP_TIMER_IN_SECONDS = 60
DEFAULT_REQUEST_TIMEOUT_IN_SECONDS = 3
COMMON_FILE_EXTENSIONS = [
    '',
    '.asmx',
    '.asmx?wsdl',
    '.aspx',
    '.asp',
    ".atom",
    ".disco",
    ".html",
    ".java",
    ".jsp",
    ".jws",
    ".jws?wsdl",
    ".php",
    ".pl",
    '.py',
    '.rss',
    '.svc',
    '.wsdl',
    '?disco',
    '?wsdl'
]


def get_arguments():
    from argparse import ArgumentParser
    parser = ArgumentParser(
        description='Use this tool to recursively crawl the web-servers within a given network '
                    'to bruteforce and discover a given URI or a list of URI\'s.')
    parser.add_argument('--uri',
                        dest='uri',
                        required=False,
                        help='An URI to search within the given network range.')
    parser.add_argument('--uri-file',
                        dest='uri_file',
                        required=False,
                        help='A new-line separated file with a list of URI\'s to bruteforce.')
    parser.add_argument('--show-code',
                        dest='show_code',
                        default=[],
                        required=False,
                        help='Optional. A comma-separated list of status codes.')
    parser.add_argument('--ip',
                        dest='ip',
                        required=False,
                        help='A single IP address to perform the parallel scanning')
    parser.add_argument('--ip-range',
                        dest='ip_range',
                        required=False,
                        help='An IP range of the class C network to find the directory. Should have a /24 suffix')
    parser.add_argument('--ip-file',
                        dest='ip_file',
                        required=False,
                        help='A txt file with a new line separated list of IP addresses.')
    parser.add_argument('--threads',
                        dest='threads',
                        default=THREAD_POOL_EXHAUSTED_LIMIT,
                        required=False,
                        help='Optional. A number of threads to use in script to scan hosts in parallel. Default is ' + str(
                            THREAD_POOL_EXHAUSTED_LIMIT))
    options = parser.parse_args()
    if not options.uri and not options.uri_file:
        parser.error('Either an URI or a file with URI\'s must be given')
    if not options.ip_range and not options.ip_file and not options.ip:
        parser.error('You have to give something to scan, use --help for more info')
    return options


import re


def read_file(file_name):
    with open(file_name, 'r', encoding='utf-8') as file:
        return [line.strip() for line in file.readlines()]


shown_emailes = set()
shown_responses = set()


def find_directory(uri_list, ip_address, show_codes):
    for uri in uri_list:
        for extension in COMMON_FILE_EXTENSIONS:
            try:
                if not uri.startswith('/'):
                    uri = '/' + uri
                if extension != '' and uri.endswith(extension):
                    uri_with_extension = uri
                else:
                    uri_with_extension = "{uri}{ext}".format(uri=uri,
                                                             ext=extension)
                resp = requests.get('http://{ip}{uri}'.format(ip=ip_address,
                                                              uri=uri_with_extension),
                                    timeout=DEFAULT_REQUEST_TIMEOUT_IN_SECONDS)
                global total_requests
                total_requests += 1

                status_code = resp.status_code
                if len(show_codes) == 0 or (len(show_codes) > 0 and status_code in show_codes):
                    html = resp.text
                    matches = re.search(r"([a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+)", html)
                    global shown_emailes
                    if matches:
                        for match in matches.groups():
                            email = str(match)
                            if email not in shown_emailes:
                                print('{ip} - {email}'.format(ip=ip_address, email=email))
                                shown_emailes.add(email)
                    global shown_responses
                    log_message = '{ip} - GET {uri} ' \
                                  '{status_code} ' \
                                  '{length} ' \
                                  '{server}'.format(ip=ip_address,
                                                    uri=uri_with_extension,
                                                    status_code=status_code,
                                                    length=len(resp.content),
                                                    server=resp.headers['server'] if 'server' in resp.headers else "")
                    if log_message not in shown_responses:
                        print(log_message)
                        shown_responses.add(log_message)
            except Exception:
                return


class JobThread:
    def __init__(self, target_function, target_function_args=None):
        assert target_function, "Function to run within the thread must be given"
        random_uid = ''.join([random.choice(string.ascii_letters
                                            + string.digits) for n in range(15)])
        self.uid = "THREAD-{uid}".format(uid=random_uid)
        self.thread = Thread(target=target_function, args=target_function_args)

    def start(self):
        self.thread.start()

    def isAlive(self):
        return self.thread.isAlive()


def create_parallel_jobs(uri_list,
                         ip_list,
                         show_codes,
                         thread_limit=THREAD_POOL_EXHAUSTED_LIMIT,
                         sleep_timer_in_seconds=SLEEP_TIMER_IN_SECONDS, ):
    if type(show_codes) == str:
        if ',' in show_codes:
            show_codes = [int(scode) for scode in show_codes.split(',')]
        else:
            show_codes = [int(show_codes)]
    spinner = [
        "▐|\\____________▌",
        "▐_|\\___________▌",
        "▐__|\\__________▌",
        "▐___|\\_________▌",
        "▐____|\\________▌",
        "▐_____|\\_______▌",
        "▐______|\\______▌",
        "▐_______|\\_____▌",
        "▐________|\\____▌",
        "▐_________|\\___▌",
        "▐__________|\\__▌",
        "▐___________|\\_▌",
        "▐____________|\\▌",
        "▐____________/|▌",
        "▐___________/|_▌",
        "▐__________/|__▌",
        "▐_________/|___▌",
        "▐________/|____▌",
        "▐_______/|_____▌",
        "▐______/|______▌",
        "▐_____/|_______▌",
        "▐____/|________▌",
        "▐___/|_________▌",
        "▐__/|__________▌",
        "▐_/|___________▌",
        "▐/|____________▌"
    ]

    def spin(refresh_rate=0.3):
        from itertools import cycle
        for c in cycle(spinner):
            print("{c}\r".format(c=c), end='', flush=True)
            sleep(refresh_rate)

    # thanks to jes_doe for a nice spinner ;3
    spinner_thread = Thread(target=spin)
    spinner_thread.start()

    threads = []
    thread_limit = int(thread_limit)

    if len(ip_list) == 1:
        # create a separate thread for each directory
        ip = ip_list[0]
        for uri in uri_list:
            create_job([ip], show_codes, sleep_timer_in_seconds, thread_limit, threads, [uri])
    else:
        # create a separate thread for each ip address
        create_job(ip_list, show_codes, sleep_timer_in_seconds, thread_limit, threads, uri_list)
    while any(thread.isAlive() for thread in threads):
        sleep(sleep_timer_in_seconds)
    print('All threads have been finished')


def create_job(ip_list, show_codes, sleep_timer_in_seconds, thread_limit, threads, uri_list):
    for i, ip in enumerate(ip_list):
        while len(threads) >= thread_limit:
            sleep(sleep_timer_in_seconds)
            for thread in threads.copy():
                if not thread.isAlive():
                    threads.remove(thread)
        try:
            thread = JobThread(target_function=find_directory, target_function_args=(uri_list, ip, show_codes))
            thread.start()
            threads.append(thread)
        except Exception as e:
            print('{exception}'.format(exception=e))


def main():
    try:
        options = get_arguments()
        if options.ip:
            ip_addresses = [options.ip]
        elif options.ip_file:
            ip_addresses = read_file(options.ip_file)
        elif options.ip_range:
            ip_addresses = []
            chunks = options.ip_range.split('.')
            for i in range(int(chunks[3].split('/')[0]), 255):
                ip_addresses.append("{}.{}.{}.{}".format(chunks[0], chunks[1], chunks[2], str(i)))
        else:
            ip_addresses = []
        uri = options.uri
        show_codes = options.show_code
        threads_limit = options.threads
        if uri:
            create_parallel_jobs([uri], ip_addresses, show_codes, threads_limit)
        list_of_uris_file_name = options.uri_file
        if list_of_uris_file_name:
            uri_list = read_file(list_of_uris_file_name)
            if uri_list:
                create_parallel_jobs(uri_list, ip_addresses, show_codes, threads_limit)
    except Exception as e:
        print(e)


if '__main__' == __name__:
    total_requests = 0
    main()
    print('Total number of HTTP requests: {req}'.format(req=total_requests))
    print('Killing all threads before exit...')
    run(['killall', 'python3'])
