#!/usr/bin/env python3
import datetime
import json
import logging
from argparse import ArgumentParser
from threading import Thread
from time import sleep

from easysnmp import Session

THREAD_POOL_EXHAUSTED_LIMIT = 10
DEFAULT_SLEEP_TIMER_IN_SECONDS = 0.5
DEFAULT_LOGGING_LEVEL = 'INFO'
DEFAULT_CONNECTION_TIMEOUT_IN_SECONDS = 3
DEFAULT_OUTPUT_FILE = 'snmp-{ip}.json'
COMMON_COMMUNITY_STRINGS = [
    'public',
    'private',
    'manager',
    'management',
    'admin',
    'login',
    'master',
    'password',
    'read',
    'smb',
    'samba'
]
COMMON_VERSIONS = [
    1,
    2
]


def current_date_time():
    return '{0:%Y-%m-%d %H:%M:%S}'.format(datetime.datetime.now())


def read_file(file_name):
    with open(file_name, 'r', encoding='utf-8') as file:
        return [line.strip() for line in file.readlines()]


def get_arguments():
    parser = ArgumentParser(
        description='Perform a parallel SNMP scan / discover on the given target(s).')
    parser.add_argument('--ip',
                        dest='ip',
                        required=False,
                        help='A single IP address to perform the SNMP scanning')
    parser.add_argument('--ip-range',
                        dest='ip_range',
                        required=False,
                        help='An IP range of the class C network to discover and enumerate SNMP agents. Should have a /24 suffix')
    parser.add_argument('--ip-file',
                        dest='ip_file',
                        required=False,
                        help='A txt file with a new line separated list of IP addresses.')
    parser.add_argument('--timeout',
                        dest='timeout',
                        default=DEFAULT_CONNECTION_TIMEOUT_IN_SECONDS,
                        required=False,
                        help='Default connection timeout timer in seconds. Default is ' + str(
                            DEFAULT_CONNECTION_TIMEOUT_IN_SECONDS))
    parser.add_argument('--threads',
                        dest='threads',
                        default=THREAD_POOL_EXHAUSTED_LIMIT,
                        required=False,
                        help='A number of threads to use in parallel. Default is ' + str(
                            THREAD_POOL_EXHAUSTED_LIMIT) + ".")
    parser.add_argument('--sleep',
                        dest='sleep',
                        default=DEFAULT_SLEEP_TIMER_IN_SECONDS,
                        required=False,
                        help='Sleep timer in seconds before spawning new threads. Default is ' + str(
                            DEFAULT_SLEEP_TIMER_IN_SECONDS))
    parser.add_argument('-l',
                        '--logging',
                        dest='logging',
                        default=DEFAULT_LOGGING_LEVEL,
                        choices=['INFO', 'DEBUG', 'WARNING', "ERROR"],
                        required=False,
                        help='Logging level. Default is ' + DEFAULT_LOGGING_LEVEL)
    options = parser.parse_args()
    return options


class SnmpThread:
    def __init__(self, target_function, target_function_args=None):
        assert target_function, "Function to run within the thread must be given"
        self.thread = Thread(target=target_function, args=target_function_args)

    def start(self):
        self.thread.start()

    def isAlive(self):
        return self.thread.isAlive()


def create_parallel_jobs(ip_list,
                         timeout,
                         thread_limit=THREAD_POOL_EXHAUSTED_LIMIT,
                         sleep_timer_in_seconds=DEFAULT_SLEEP_TIMER_IN_SECONDS):
    threads = []
    for ip in ip_list:
        while len(threads) >= thread_limit:
            sleep(sleep_timer_in_seconds)
            for thread in threads.copy():
                if not thread.isAlive():
                    threads.remove(thread)
        try:
            thread = SnmpThread(target_function=enumerate_snmp, target_function_args=(ip, timeout))
            thread.start()
            threads.append(thread)
        except Exception as e:
            logging.error('{exception}'.format(exception=e))

    while any(thread.isAlive() for thread in threads):
        sleep(sleep_timer_in_seconds)


def enumerate_versions(ip, community, timeout):
    for version in COMMON_VERSIONS:
        try:
            logging.debug(
                '{ip} - Initiating session with "{community}" on version {version}'.format(ip=ip,
                                                                                           community=community,
                                                                                           version=version))
            session = Session(hostname=ip,
                              community=community,
                              version=version,
                              timeout=timeout)
            return session.walk()
        except Exception as error:
            if 'returned NULL without setting an error' in str(error):
                logging.debug('{ip} - Failed to enumerate with "{community}" on version {version}'.format(ip=ip,
                                                                                                          community=community,
                                                                                                          version=version))
                continue
            logging.debug("{ip} - {error}".format(ip=ip, error=error))


def establish_session_and_walk(ip, timeout):
    for community in COMMON_COMMUNITY_STRINGS:
        items = enumerate_versions(ip, community, timeout)
        if items:
            return items


def enumerate_snmp(ip, timeout):
    try:
        # finding the correct version
        items = establish_session_and_walk(ip, timeout)
        results = []
        for item in items:
            oid, oid_index = item.oid, item.oid_index
            value = item.value
            snmp_type = item.snmp_type
            results.append({
                'oid': oid,
                'oid_index': oid_index,
                'value': value,
                'snmp_type': snmp_type})
        if results:
            logging.info(
                "{ip} - SNMP agent enumerated, number of stored MIB value: {len}".format(ip=ip, len=len(results)))
            with open(DEFAULT_OUTPUT_FILE.format(ip=ip), 'a', encoding='utf-8') as file:
                json.dump({'ip': ip, 'snmp': results}, file)
                file.write('\n')
    except Exception as error:
        logging.debug('{ip} - {error}'.format(ip=ip, error=error))


options = get_arguments()
logging.getLogger('easysnmp.interface').propagate = False
logging.basicConfig(
    format='[%(levelname)s] - %(message)s',
    datefmt='%m/%d/%Y %I:%M:%S %p',
    level=options.logging)

try:
    logging.info('SNMP scan started at {now}'.format(now=current_date_time()))
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

    create_parallel_jobs(ip_addresses,
                         timeout=int(options.timeout),
                         thread_limit=int(options.threads),
                         sleep_timer_in_seconds=int(options.sleep))
    logging.info('SNMP scan finished at {now}'.format(now=current_date_time()))
except Exception as e:
    logging.error(e)
    exit(1)
