#!/usr/bin/env python3

import random
import string
from subprocess import call as run
from threading import Thread
from time import sleep

import requests

THREAD_POOL_EXHAUSTED_LIMIT = 10
SLEEP_TIMER_IN_SECONDS = 10
DEFAULT_OUTPUT_DIRECTORY = 'async-sqlmap'
DEFAULT_SLEEP_TIMER_IN_SECONDS = 60

COMMON_FILE_EXTENSIONS = ['.php', '.html', '.asp', '.aspx', '.py', '.txt', '']


def get_arguments():
    from argparse import ArgumentParser
    parser = ArgumentParser(
        description='Use this tool to recursively crawl the web-servers in a given network to find a given directory.')
    parser.add_argument('--uri', dest='uri',
                        required=True,
                        help='An URI to search within the given network range.')
    parser.add_argument('--show-code',
                        dest='show_code',
                        default=[],
                        required=False,
                        help='Optional. A comma-separated list of status codes.')
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
    if not options.ip_range and not options.ip_file:
        parser.error('Either an IP range or a file with IP addresses must be given')
    return options


def read_ip_addresses(file_name):
    with open(file_name, 'r', encoding='utf-8') as file:
        return [line.strip() for line in file.readlines()]


def find_directory(uri, ip_address, show_codes):
    for extension in COMMON_FILE_EXTENSIONS:
        try:
            uri_with_extension = "{uri}{ext}".format(uri=uri,
                                                     ext=extension)
            resp = requests.get('http://{ip}{uri}'.format(ip=ip_address,
                                                          uri=uri_with_extension))
            status_code = resp.status_code
            if len(show_codes) == 0 or (len(show_codes) > 0 and status_code in show_codes):
                log_message = '[{ip}] GET {uri} ' \
                              '{status_code} ' \
                              '{length} ' \
                              '{server}'.format(ip=ip_address,
                                                uri=uri_with_extension,
                                                status_code=status_code,
                                                length=len(resp.content),
                                                server=resp.headers['server'] if 'server' in resp.headers else "")
                print(log_message)
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


def create_parallel_jobs(uri,
                         ip_list,
                         show_codes,
                         thread_limit=THREAD_POOL_EXHAUSTED_LIMIT,
                         sleep_timer_in_seconds=SLEEP_TIMER_IN_SECONDS, ):
    if type(show_codes) == str:
        if ',' in show_codes:
            show_codes = [int(scode) for scode in show_codes.split(',')]
        else:
            show_codes = [int(show_codes)]
    threads = []

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
            print("{}\r".format(c), end='', flush=True)
            sleep(refresh_rate)

    spinner_thread = Thread(target=spin)
    spinner_thread.start()

    for i, ip in enumerate(ip_list):
        while len(threads) >= thread_limit:
            print('{spinner_width} {i}/{len}\r'.format(spinner_width=len(spinner[0]) * ' ', i=i, len=len(ip_list)), end='', flush=True)
            sleep(sleep_timer_in_seconds)
            for thread in threads.copy():
                if not thread.isAlive():
                    threads.remove(thread)
        try:
            thread = JobThread(target_function=find_directory, target_function_args=(uri, ip, show_codes))
            thread.start()
            threads.append(thread)
        except Exception as e:
            print('{exception}'.format(exception=e))

    while any(thread.isAlive() for thread in threads):
        sleep(sleep_timer_in_seconds)
    print('All threads have been finished')


def main():
    try:
        options = get_arguments()
        if options.ip_file:
            ip_addresses = read_ip_addresses(options.ip_file)
        elif options.ip_range:
            ip_addresses = []
            chunks = options.ip_range.split('.')
            for i in range(int(chunks[3].split('/')[0]), 255):
                ip_addresses.append("{}.{}.{}.{}".format(chunks[0], chunks[1], chunks[2], str(i)))
        else:
            ip_addresses = []
        create_parallel_jobs(options.uri, ip_addresses, options.show_code, int(options.threads))
    except Exception as e:
        print(e)
    print('Killing all threads before exit...')
    run(['killall', 'python3'])


if '__main__' == __name__:
    main()
