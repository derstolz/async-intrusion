#!/usr/bin/env python3
import datetime
import logging
from threading import Thread
from time import sleep

from requests import Session

DEFAULT_LOGGING_LEVEL = 'INFO'
FUZZ_PLACEHOLDER = 'FUZZ'

THREAD_POOL_EXHAUSTED_LIMIT = 10
DEFAULT_SLEEP_TIMER_IN_SECONDS = 0.5
DEFAULT_SOCKET_TIMEOUT_IN_SECONDS = 3

HTTP_METHODS = ['HEAD', 'GET', 'POST', 'PATCH', 'DELETE']


def current_date_time():
    return '{0:%Y-%m-%d %H:%M:%S}'.format(datetime.datetime.now())


def get_arguments():
    from argparse import ArgumentParser
    parser = ArgumentParser()
    parser.add_argument('--url',
                        dest='url',
                        required=True,
                        help='An URL of the target web-site to fuzz')
    parser.add_argument('--method',
                        dest='method',
                        required=False,
                        default='GET',
                        choices=HTTP_METHODS,
                        help='HTTP method to use. Default is GET')
    parser.add_argument('--headers',
                        dest='headers',
                        required=False,
                        nargs="+",
                        default=['User-Agent'],
                        help='A space separated list of headers to use while injecting the payload.')
    parser.add_argument('--data',
                        dest='data',
                        required=False,
                        help='HTTP body message to send. You should paste your placeholder to fuzz as "FUZZ"')
    parser.add_argument('--wordlist',
                        dest='wordlist',
                        required=False,
                        help='A wordlist with payloads to use while fuzzing the target')
    parser.add_argument('-l',
                        '--logging',
                        dest='logging',
                        required=False,
                        default=DEFAULT_LOGGING_LEVEL,
                        choices=['INFO', 'DEBUG', 'WARNING', "ERROR"],
                        help='Logging level. '
                             f'Default is {DEFAULT_LOGGING_LEVEL}')
    parser.add_argument('--threads',
                        dest='threads',
                        required=False,
                        default=THREAD_POOL_EXHAUSTED_LIMIT,
                        type=int,
                        help='A number of threads to use in parallel. '
                             f'Default is {THREAD_POOL_EXHAUSTED_LIMIT}.')
    parser.add_argument('--sleep',
                        dest='sleep',
                        required=False,
                        default=DEFAULT_SLEEP_TIMER_IN_SECONDS,
                        type=int,
                        help='Sleep timer in seconds before spawning new threads. '
                             f'Default is {DEFAULT_SLEEP_TIMER_IN_SECONDS}')

    options = parser.parse_args()
    return options


def send(method, url, headers, body_data):
    try:
        logging.debug('{method} {url} - {headers}'.format(method=method,
                                                          url=url,
                                                          headers=headers))
        with Session() as session:
            session.headers = headers
            if method == 'HEAD':
                if body_data:
                    raise Exception('HTTP body message can not be used in combination with HEAD or GET request')
                resp = session.head(url)
            elif method == 'GET':
                if body_data:
                    raise Exception('HTTP body message can not be used in combination with HEAD or GET request')
                resp = session.get(url)
            elif method == 'POST':
                resp = session.post(url, data=body_data)
            elif method == 'PATCH':
                resp = session.patch(url, data=body_data)
            elif method == 'DELETE':
                resp = session.delete(url, data=body_data)
            else:
                raise Exception(f'Unsupported HTTP method: {method}')
            return resp
    except Exception as e:
        logging.error(f'{url} - {e}')


def create_fuzz_thread(method, url, header_names, body_data, payload):
    headers_with_payload = {}
    for header in header_names:
        headers_with_payload[header] = payload
    if body_data:
        body_data_with_payload = body_data.replace(FUZZ_PLACEHOLDER, payload)
    else:
        body_data_with_payload = body_data
    if FUZZ_PLACEHOLDER in url:
        url = url.replace(FUZZ_PLACEHOLDER, payload)
    resp = send(method, url, headers_with_payload, body_data_with_payload)
    resp_len = len(resp.content)
    global known_resp_len
    global total_number_of_http_requests
    total_number_of_http_requests += 1
    if resp_len not in known_resp_len:
        logging.info(f'{method} {url} - {resp.status_code} {resp_len}')
        logging.debug(f"{method} {url} - {resp.text}")
        known_resp_len.add(resp_len)
    else:
        logging.debug(f'{method} {url} - {resp.status_code} {resp_len}')


def create_parallel_jobs(method, url, header_names, body_data, wordlist,
                         thread_limit=THREAD_POOL_EXHAUSTED_LIMIT,
                         sleep_timer_in_seconds=DEFAULT_SLEEP_TIMER_IN_SECONDS):
    threads = []
    for payload in wordlist:
        while len(threads) >= thread_limit:
            sleep(sleep_timer_in_seconds)
            for thread in threads.copy():
                if not thread.isAlive():
                    threads.remove(thread)
        try:
            thread = Thread(target=create_fuzz_thread, args=(method, url, header_names, body_data, payload))
            thread.start()
            threads.append(thread)
        except Exception as e:
            logging.error(e)

    while any(thread.isAlive() for thread in threads):
        sleep(sleep_timer_in_seconds)


options = get_arguments()
logging.basicConfig(
    format='[%(levelname)s] - %(message)s',
    datefmt='%m/%d/%Y %I:%M:%S %p',
    level=options.logging)
logging.getLogger('urllib3.connectionpool').propagate = False
url = options.url
if options.wordlist:
    with open(options.wordlist, 'r', encoding='utf-8', errors='ignore') as f:
        wordlist = [line.strip() for line in f.readlines() if line.strip()]
else:
    wordlist = ["A"]
    counter = 100
    while len(wordlist) <= 30:
        wordlist.append("A" * counter)
        counter += 200

logging.info(f'Web server fuzzing started at {current_date_time()}')
known_resp_len = set()
total_number_of_http_requests = 0
create_parallel_jobs(options.method, url, options.headers, options.data, wordlist,
                     thread_limit=options.threads,
                     sleep_timer_in_seconds=options.sleep)
logging.info(f'Web server fuzzing finished at {current_date_time()}')
logging.info(f'Total number of HTTP requests: {total_number_of_http_requests}')
logging.info(f'Total number of HTTP responses with different length: {len(known_resp_len)}')
