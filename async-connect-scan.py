#!/usr/bin/env python3
import logging
from argparse import ArgumentParser
from threading import Thread
from time import sleep

THREAD_POOL_EXHAUSTED_LIMIT = 10
DEFAULT_SLEEP_TIMER_IN_SECONDS = 0.5
DEFAULT_PORT_RANGE = '0-2100'
DEFAULT_LOGGING_LEVEL = 'INFO'
DEFAULT_SOCKET_TIMEOUT_IN_SECONDS = 3


def current_date_time():
    return '{0:%Y-%m-%d %H:%M:%S}'.format(datetime.datetime.now())


def get_arguments():
    parser = ArgumentParser(
        description='Perform a parallel TCP Connect scan on the given target.')
    parser.add_argument('--ip',
                        dest='ip',
                        required=True,
                        help='An IP address of the target to perform the parallel TCP connect scan on')
    parser.add_argument('--port-range',
                        dest='port_range',
                        default=DEFAULT_PORT_RANGE,
                        required=False,
                        help='TCP ports range to scan. Default is ' + DEFAULT_PORT_RANGE)
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
    return options


class ConnectThread:
    def __init__(self, target_function, target_function_args=None):
        assert target_function, "Function to run within the thread must be given"
        self.thread = Thread(target=target_function, args=target_function_args)

    def start(self):
        self.thread.start()

    def isAlive(self):
        return self.thread.isAlive()


def create_parallel_jobs(ip, port_range, timeout,
                         thread_limit=THREAD_POOL_EXHAUSTED_LIMIT,
                         sleep_timer_in_seconds=DEFAULT_SLEEP_TIMER_IN_SECONDS):
    threads = []
    for i, port in enumerate(port_range):
        while len(threads) >= thread_limit:
            sleep(sleep_timer_in_seconds)
            for thread in threads.copy():
                if not thread.isAlive():
                    threads.remove(thread)
        try:
            thread = ConnectThread(target_function=connect, target_function_args=(ip, port, timeout))
            thread.start()
            threads.append(thread)
        except Exception as e:
            logging.error('{exception}'.format(exception=e))

    while any(thread.isAlive() for thread in threads):
        sleep(sleep_timer_in_seconds)


import socket


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


options = get_arguments()
logging.basicConfig(
    format='[%(levelname)s] - %(message)s',
    datefmt='%m/%d/%Y %I:%M:%S %p',
    level=options.logging)
import datetime

try:
    logging.info('TCP Connect scan started at {now}'.format(now=current_date_time()))
    create_parallel_jobs(options.ip,
                         port_range=range(int(options.port_range.split('-')[0]), int(options.port_range.split('-')[1])),
                         timeout=int(options.timeout),
                         thread_limit=int(options.threads),
                         sleep_timer_in_seconds=int(options.sleep))
    logging.info('TCP Connect scan finished at {now}'.format(now=current_date_time()))
except Exception as e:
    logging.error(e)
    exit(1)
