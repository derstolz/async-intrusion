#!/usr/bin/env python3
import logging
from argparse import ArgumentParser
from threading import Thread
from time import sleep

THREAD_POOL_EXHAUSTED_LIMIT = 10
DEFAULT_SLEEP_TIMER_IN_SECONDS = 0.5
DEFAULT_LOGGING_LEVEL = 'INFO'
DEFAULT_SOCKET_TIMEOUT_IN_SECONDS = 3

import datetime


def current_date_time():
    return '{0:%Y-%m-%d %H:%M:%S}'.format(datetime.datetime.now())


def get_arguments():
    parser = ArgumentParser(
        description='Perform a parallel TCP Connect scan on the given target.')
    parser.add_argument('--ip',
                        dest='ip',
                        required=False,
                        help='A single IP address to perform the Connect scanning')
    parser.add_argument('--ip-range',
                        dest='ip_range',
                        required=False,
                        help='An IP range of the class C network to perform parallel scanning. Should have a /24 suffix')
    parser.add_argument('--ip-file',
                        dest='ip_file',
                        required=False,
                        help='A txt file with a new line separated list of IP addresses.')
    parser.add_argument('--port',
                        dest='port',
                        required=False,
                        help='A single TCP port to scan. Sometimes you may want to scan one port on the different machines.')
    parser.add_argument('--port-range',
                        dest='port_range',
                        required=False,
                        help='TCP ports range to scan, in the following format: 20-110')
    parser.add_argument('--timeout',
                        dest='timeout',
                        default=DEFAULT_SOCKET_TIMEOUT_IN_SECONDS,
                        required=False,
                        help='Default socket timeout timer in seconds. Default is ' + str(
                            DEFAULT_SOCKET_TIMEOUT_IN_SECONDS))
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
                        help='Sleep timer in seconds before spawning new threads. Defailt is ' + str(
                            DEFAULT_SLEEP_TIMER_IN_SECONDS))
    parser.add_argument('-l',
                        '--logging',
                        dest='logging',
                        default=DEFAULT_LOGGING_LEVEL,
                        choices=['INFO', 'DEBUG', 'WARNING', "ERROR"],
                        required=False,
                        help='Logging level. Default is ' + DEFAULT_LOGGING_LEVEL)
    options = parser.parse_args()
    if not options.ip_range and not options.ip_file and not options.ip:
        parser.error('You have to give something to scan, use --help for more info')
    if not options.port_range and not options.port:
        parser.error('You have to give either a port range or a port number')
    return options


def connect(ip, port, timeout):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        sock.connect((ip, port))
        logging.info('{ip}: {port}/tcp open'.format(ip=ip, port=port))
        sock.close()
    except socket.timeout:
        logging.debug('{ip}: {port}/tcp timed out'.format(ip=ip, port=port))
    except ConnectionRefusedError:
        logging.debug('{ip}: {port}/tcp connection refused'.format(ip=ip, port=port))
    except ConnectionResetError:
        logging.debug('{ip}: {port}/tcp connection reset'.format(ip=ip, port=port))
    except ConnectionError:
        logging.debug('{ip}: {port}/tcp connection error'.format(ip=ip, port=port))
    except OSError as error:
        logging.debug('{ip}: {port}/tcp {error}'.format(ip=ip, port=port, error=error))
    except Exception as error:
        logging.debug('{ip}: {port}/tcp {error}'.format(ip=ip, port=port, error=error))


class ConnectThread:
    def __init__(self, target_function, target_function_args=None):
        assert target_function, "Function to run within the thread must be given"
        self.thread = Thread(target=target_function, args=target_function_args)

    def start(self):
        self.thread.start()

    def isAlive(self):
        return self.thread.isAlive()


def create_scan_thread(ip, port, timeout, threads, thread_limit, sleep_timer_in_seconds):
    while len(threads) >= thread_limit:
        sleep(sleep_timer_in_seconds)
        for thread in threads.copy():
            if not thread.isAlive():
                threads.remove(thread)
    try:
        thread = ConnectThread(target_function=connect, target_function_args=(ip, port, timeout))
        threads.append(thread)
        thread.start()
    except Exception as e:
        logging.error('{exception}'.format(exception=e))


def create_parallel_jobs(ip_addresses,
                         port_range=None,
                         port=None,
                         timeout=DEFAULT_SOCKET_TIMEOUT_IN_SECONDS,
                         thread_limit=THREAD_POOL_EXHAUSTED_LIMIT,
                         sleep_timer_in_seconds=DEFAULT_SLEEP_TIMER_IN_SECONDS):
    assert port_range or port
    threads = []
    if port_range:
        for ip in ip_addresses:
            for i, port in enumerate(port_range):
                create_scan_thread(ip, port,
                                   timeout=timeout,
                                   threads=threads,
                                   thread_limit=thread_limit,
                                   sleep_timer_in_seconds=sleep_timer_in_seconds)
    elif port:
        for ip in ip_addresses:
            create_scan_thread(ip, port,
                               timeout=timeout,
                               threads=threads,
                               thread_limit=thread_limit,
                               sleep_timer_in_seconds=sleep_timer_in_seconds)
    while any(thread.isAlive() for thread in threads):
        sleep(sleep_timer_in_seconds)


import socket


def read_file(file_name):
    with open(file_name, 'r', encoding='utf-8') as file:
        return [line.strip() for line in file.readlines()]


options = get_arguments()
logging.basicConfig(
    format='[%(levelname)s] - %(message)s',
    datefmt='%m/%d/%Y %I:%M:%S %p',
    level=options.logging)

try:
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
    logging.info('TCP Connect scan started at {now}'.format(now=current_date_time()))
    if options.port_range:
        port_range = range(int(options.port_range.split('-')[0]), int(options.port_range.split('-')[1]))
        create_parallel_jobs(ip_addresses,
                             port_range=port_range,
                             port=None,
                             timeout=int(options.timeout),
                             thread_limit=int(options.threads),
                             sleep_timer_in_seconds=int(options.sleep))
    elif options.port:
        create_parallel_jobs(ip_addresses,
                             port_range=None,
                             port=int(options.port),
                             timeout=int(options.timeout),
                             thread_limit=int(options.threads),
                             sleep_timer_in_seconds=int(options.sleep)
                             )
    logging.info('TCP Connect scan finished at {now}'.format(now=current_date_time()))
except Exception as e:
    logging.error(e)
    exit(1)
