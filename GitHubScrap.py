#!/usr/bin/env python3

# GitHubScrap is a simple Python 3 script that automates GitHub OSINT during early stages of Red Team exercises
# author - mamatb (t.me/m_amatb)
# location - https://github.com/mamatb/GitHubScrap
# style guide - https://google.github.io/styleguide/pyguide.html

# TODO
#
# use colored output
# report new findings via slack notifications
# classify findings by query term and github type
# parse web forms instead of forging them
# use argument parser (argparse)
# create requirements.txt file
# slow down queries (https://developer.github.com/v3/search/#rate-limit)

import sys
import os
import re
import requests
import json
import pyotp
import datetime
from urllib.parse import urlencode, quote_plus
from bs4 import BeautifulSoup

class MsgException(Exception):
    def __init__(self, message, exception, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.message = message
        self.exception = exception

def panic(msg_exception):
    """exception handling"""

    print(
        f'[!] Error! {msg_exception.message}:\n'
        f'    {msg_exception.exception}'
    , file = sys.stderr)

def print_usage():
    """usage printing"""

    print(
        '[!] Wrong syntax. Usage:\n'
        '    python3 gitsearch.py <config_file> <output_file>'
    , file = sys.stderr)

def print_info(message):
    """additional info printing"""

    print(f'[!] Info: {message}', file = sys.stdout)

def load_config(config_path):
    """json config file reading"""

    try:
        with open(config_path, 'r') as config_file:
            config_json = json.load(config_file)
            github_username = config_json.get('github_username')
            github_password = config_json.get('github_password')
            github_otp = config_json.get('github_otp')
            github_query_exact = config_json.get('github_query_exact')
            github_query_terms = config_json.get('github_query_terms')
    except Exception as exception:
        raise MsgException('Config file could not be read', exception)
    return github_username, github_password, github_otp, github_query_exact, github_query_terms

def save_output(data_input, output_path):
    """json output file writing"""

    try:
        if os.path.exists(output_path):
            with open(output_path, 'r+') as output_file:
                data_file = json.load(output_file)
                data_input.update(data_file)
                output_file.seek(0)
                json.dump(data_input, output_file)
        else:
            with open(output_path, 'w') as output_file:
                json.dump(data_input, output_file)
    except Exception as exception:
        raise MsgException('Output file could not be written', exception)

def github_login(github_http_session, github_username, github_password, github_otp):
    """github logging in (3 requests needed)"""

    try: # 1st request (grab some data needed for the login form)
        github_html_login = github_http_session.get(
            'https://github.com/login',
        )
        github_soup_login = BeautifulSoup(github_html_login.text, 'html.parser')
        data = {
            'commit': 'Sign in',
            'authenticity_token': github_soup_login.find('input', {'name': 'authenticity_token'})['value'],
            'login': github_username,
            'password': github_password,
            'webauthn-support': 'supported',
            'webauthn-iuvpaa-support': 'unsupported',
            github_soup_login.find('input', {'name': re.compile('required_field_')})['name']: '',
            'timestamp': github_soup_login.find('input', {'name': 'timestamp'})['value'],
            'timestamp_secret': github_soup_login.find('input', {'name': 'timestamp_secret'})['value'],
        }
    except Exception as exception:
        raise MsgException('Unable to HTTP-GET GitHub login data', exception)

    try: # 2nd request (submit the login form and grab some data needed for the OTP form)
        github_http_session.headers.update({'Content-Type': 'application/x-www-form-urlencoded'})
        github_html_twofactor = github_http_session.post(
            'https://github.com/session',
            data = urlencode(data),
        )
        github_soup_twofactor = BeautifulSoup(github_html_twofactor.text, 'html.parser')
        data = {
            'authenticity_token': github_soup_twofactor.find('input', {'name': 'authenticity_token'})['value'],
        }
    except Exception as exception:
        raise MsgException('Unable to log in to GitHub (credentials)', exception)

    try: # 3rd request (submit the OTP form)
        data.update({'otp': pyotp.TOTP(github_otp).now()})
        github_http_session.post(
            'https://github.com/sessions/two-factor',
            data = urlencode(data),
        )
        github_http_session.headers.pop('Content-Type')
    except Exception as exception:
        raise MsgException('Unable to log in to GitHub (OTP)', exception)

def github_search_count(github_http_session, github_query_term, github_type):
    """search results count"""

    try:
        github_html_count = github_http_session.get(
            f'https://github.com/search/count?q={quote_plus(github_query_term)}&type={quote_plus(github_type)}',
        )
        github_soup_count = BeautifulSoup(github_html_count.text, 'html.parser')
        github_count = github_soup_count.span.text
    except Exception as exception:
        raise MsgException('Unable to count GitHub search results', exception)
    return github_count

def github_search_retrieval(github_http_session, github_query_term, github_type):
    """search results retrieval"""

    try:
        github_html_pages = github_http_session.get(
            f'https://github.com/search?o=desc&q={quote_plus(github_query_term)}&type={quote_plus(github_type)}',
        )
        github_soup_pages = BeautifulSoup(github_html_pages.text, 'html.parser')
        github_pages_tag = github_soup_pages.find('em', {'data-total-pages': True})
        github_pages = github_pages_tag['data-total-pages'] if github_pages_tag else 1
        data = {}
        for github_page in range(int(github_pages)):
            github_html_page = github_http_session.get(
                f'https://github.com/search?o=desc&p={github_page + 1}&q={quote_plus(github_query_term)}&type={quote_plus(github_type)}',
            )
            github_soup_page = BeautifulSoup(github_html_page.text, 'html.parser')
            github_search_date = datetime.datetime.now().strftime('%F %T')
            for github_search_result in github_soup_page.find_all('a', {'data-hydro-click': True}):
                data.update({f'''https://github.com{github_search_result['href']}''': f'{github_search_date}'})
    except Exception as exception:
        raise MsgException('Unable to retrieve GitHub search results', exception)
    return data

def github_logout(github_http_session):
    """github logging out (2 requests needed)"""

    try: # 1st request (grab some data needed for the logout form)
        github_html_root = github_http_session.get(
            'https://github.com',
        )
        github_soup_root = BeautifulSoup(github_html_root.text, 'html.parser')
        data = {
            'authenticity_token': github_soup_root.find('input', {'name': 'authenticity_token'})['value'],
        }
    except Exception as exception:
        raise MsgException('Unable to HTTP-GET GitHub logout data', exception)

    try: # 2nd request (submit the logout form)
        github_http_session.headers.update({'Content-Type': 'application/x-www-form-urlencoded'})
        github_http_session.post(
            'https://github.com/logout',
            data = urlencode(data),
        )
        github_http_session.headers.pop('Content-Type')
    except Exception as exception:
        raise MsgException('Unable to log out from GitHub', exception)

def main():
    if len(sys.argv) != 3:
        print_usage()
        sys.exit(-1)
    try:
        github_username, github_password, github_otp, github_query_exact, github_query_terms = load_config(sys.argv[1])
        if github_query_exact:
            for term_index, term_value in enumerate(github_query_terms):
                github_query_terms[term_index] = f'"{term_value}"'
        github_http_session = requests.session()
        headers = {
            'User-Agent': 'Mozilla Firefox Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:53.0) Gecko/20100101 Firefox/53.0',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Encoding': 'gzip, deflate',
            'Accept-Language': 'en,es;q=0.5',
            'Connection': 'close',
            'Referer': 'https://github.com/',
        }
        github_http_session.headers.update(headers)
        github_login(github_http_session, github_username, github_password, github_otp)
        github_types = [
            'repositories',
            'code',
            'commits',
            'issues',
            'discussions',
            'packages',
            'marketplace',
            'topics',
            'wikis',
            'users',
        ]
        for github_query_term in github_query_terms:
            for github_type in github_types:                
                github_count = github_search_count(github_http_session, github_query_term, github_type)
                print_info(
                    f'{github_count} results while looking for {github_query_term} ({github_type})'
                )
                if github_count != '0':
                    save_output(github_search_retrieval(github_http_session, github_query_term, github_type), sys.argv[2])
    except MsgException as msg_exception:
        panic(msg_exception)
    finally:
        try:
            github_logout(github_http_session)
            github_http_session.close()
        except:
            sys.exit(-1)

if __name__ == '__main__':
    main()
