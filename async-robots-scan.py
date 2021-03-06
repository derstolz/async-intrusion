#!/usr/bin/env python3
import requests

DEFAULT_LOGGING_LEVEL = 'INFO'
from time import sleep

from threading import Thread

THREAD_POOL_EXHAUSTED_LIMIT = 10
DEFAULT_SLEEP_TIMER_IN_SECONDS = 0.5


def get_arguments():
    from argparse import ArgumentParser

    parser = ArgumentParser(
                description='Use this script to discover and crawl URL entries in a robots.txt file in a web '
                            'application')
    parser.add_argument('--robots-url',
                        dest='robots_url',
                        required=True,
                        help='An URL to the robots.txt file')
    parser.add_argument('--show-code',
                        dest='show_code',
                        default=[],
                        required=False,
                        help='Optional. A comma-separated list of status codes to print out.')
    parser.add_argument('-l',
                        '--logging',
                        dest='logging',
                        default=DEFAULT_LOGGING_LEVEL,
                        choices=['INFO', 'DEBUG', 'WARNING', "ERROR"],
                        required=False,
                        help='Logging level. Default is ' + DEFAULT_LOGGING_LEVEL)
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

    options = parser.parse_args()
    return options


def download_robots_file(robots_url):
    assert robots_url

    try:
        resp = requests.get(robots_url)
        status_code = resp.status_code
        if status_code == 200:
            logging.info('Robots file has been downloaded')
            return resp.text
        else:
            logging.error("Unexpected status code: {status_code}"
                          .format(status_code=status_code))
    except Exception as e:
        logging.error(e)


def visit_url(robots_url, robots_uri, show_codes):
    base_url = robots_url.replace('/robots.txt', '')
    url = base_url + robots_uri
    try:
        resp = requests.get(url)
        status_code = resp.status_code

        if not show_codes or status_code in show_codes:
            logging.info('{url} - {status_code} {len}'
                         .format(url=url, status_code=status_code, len=len(resp.content)))
        else:
            logging.debug('{url} - {status_code} {len}'
                          .format(url=url, status_code=status_code, len=len(resp.content)))
    except Exception as e:
        logging.debug("{url} - Unexpected error: {error}".format(url=url, error=e))


def create_parallel_jobs(robots_url_list, show_codes,
                         thread_limit=THREAD_POOL_EXHAUSTED_LIMIT,
                         sleep_timer_in_seconds=DEFAULT_SLEEP_TIMER_IN_SECONDS):
    threads = []
    for uri in robots_url_list:
        while len(threads) >= thread_limit:
            sleep(sleep_timer_in_seconds)
            for thread in threads.copy():
                if not thread.isAlive():
                    threads.remove(thread)
        try:
            thread = Thread(target=visit_url, args=(robots_url, uri, show_codes))
            thread.start()
            threads.append(thread)
        except Exception as e:
            logging.error('{exception}'.format(exception=e))

    while any(thread.isAlive() for thread in threads):
        sleep(sleep_timer_in_seconds)


import logging

options = get_arguments()
logging.basicConfig(
            format='[%(levelname)s] - %(message)s',
            datefmt='%m/%d/%Y %I:%M:%S %p',
            level=options.logging)
logging.getLogger('urllib3.connectionpool').propagate = False

options = get_arguments()

if ',' in options.show_code:
    show_codes = [int(code) for code in options.show_code.split(',')]
elif options.show_code:
    show_codes = [int(options.show_code)]
else:
    show_codes = []
robots_url = options.robots_url

logging.info('Downloading {url}'.format(url=robots_url))
robots = download_robots_file(robots_url)
allowed_url_list_from_robots = [line.split(': ')[1] for line in robots.split('\n')
                                if 'Allow: ' in line]
disallowed_url_list_from_robots = [line.split(': ')[1] for line in robots.split('\n')
                                   if 'Disallow: ' in line]
logging.info("{len} allowed urls have been collected"
             .format(len=len(allowed_url_list_from_robots)))
logging.info("{len} disallowed urls have been collected"
             .format(len=len(disallowed_url_list_from_robots)))

logging.info('Crawling all allowed entries')
create_parallel_jobs(robots_url_list=allowed_url_list_from_robots,
                     show_codes=show_codes,
                     thread_limit=int(options.threads),
                     sleep_timer_in_seconds=int(options.sleep))
logging.info('Crawling all disallowed entries')
create_parallel_jobs(robots_url_list=disallowed_url_list_from_robots,
                     show_codes=show_codes,
                     thread_limit=int(options.threads),
                     sleep_timer_in_seconds=int(options.sleep))
