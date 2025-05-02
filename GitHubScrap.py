#!/usr/bin/env python3

# GitHubScrap is a simple Python 3 script that automates GitHub OSINT during early stages of Red Team exercises
# author - mamatb (t.me/m_amatb)
# location - https://github.com/mamatb/GitHubScrap
# style guide - https://google.github.io/styleguide/pyguide.html

import datetime
import json
from os import path
import re
import sys
import time
from urllib import parse

import bs4
import pyotp
import requests

GITHUB_HTTP_DELAY = 1.5
SLACK_HTTP_DELAY = 1.5


class MsgException(Exception):
    def __init__(self, exception, message='Unknown error', *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.message = message
        self.exception = exception

    def __str__(self):
        return f'[!] Error! {self.message}:\n    {self.exception}'

    def panic(self):
        print(self, file=sys.stderr)


def print_usage():
    """Print usage."""
    print(
        '[!] Wrong syntax. Usage:\n'
        '    python3 GitHubScrap.py <config_file> <output_file>',
        file=sys.stderr
    )


def print_info(message):
    """Print additional information."""
    print(f'[!] Info: {message}', file=sys.stderr)


def load_config(config_path):
    """Read JSON config file."""
    try:
        with open(config_path) as config_file:
            config_json = json.load(config_file)
            github_username = config_json.get('github_username')
            github_password = config_json.get('github_password')
            github_otp = config_json.get('github_otp')
            github_query_exact = config_json.get('github_query_exact')
            github_query_terms = config_json.get('github_query_terms')
            slack_webhook = config_json.get('slack_webhook')
        return github_username, github_password, github_otp, github_query_exact, github_query_terms, slack_webhook
    except Exception as e:
        raise MsgException(e, 'Unable to read config file')


def save_output_return_unseen(urls_dict_new, output_path):
    """Write JSON output file."""
    try:
        urls_new = set(urls_dict_new.keys())
        urls_old = {}
        if path.exists(output_path):
            with open(output_path, 'r+') as output_file:
                urls_dict_old = json.load(output_file)
                urls_old = set(urls_dict_old.keys())
                urls_dict_new.update(urls_dict_old)
                output_file.seek(0)
                json.dump(urls_dict_new, output_file)
        else:
            with open(output_path, 'w') as output_file:
                json.dump(urls_dict_new, output_file)
        return urls_new.difference(urls_old)
    except Exception as e:
        raise MsgException(e, 'Unable to write output file')


def notify_slack(urls_unseen, slack_webhook):
    """Notify Slack through webhook."""
    try:
        print_info('sending Slack notifications ...')
        slack_http_headers = {
            'User-Agent': 'GitHubScrap',
            'Content-type': 'application/json',
        }
        slack_http_data = {}
        urls_string = ''
        urls_count = 0
        for url in urls_unseen:
            urls_string += f'{url}\n'
            urls_count += 1
            if urls_count % 8 == 0:
                slack_http_data.update({
                    'text': urls_string,
                })
                requests.post(
                    slack_webhook,
                    headers=slack_http_headers,
                    data=json.dumps(slack_http_data),
                )
                time.sleep(SLACK_HTTP_DELAY)
                urls_string = ''
        if len(urls_string) != 0:
            slack_http_data.update({
                'text': urls_string,
            })
            requests.post(
                slack_webhook,
                headers=slack_http_headers,
                data=json.dumps(slack_http_data),
            )
            time.sleep(SLACK_HTTP_DELAY)
            urls_string = ''
    except Exception as e:
        raise MsgException(e, 'Unable to send Slack notifications')


def github_login(github_http_session, github_username, github_password, github_otp):
    """Log in to GitHub (3 requests needed)."""
    try:  # 1st request (grab some data needed for the login form)
        github_html_login = github_http_session.get(
            'https://github.com/login',
        )
        time.sleep(GITHUB_HTTP_DELAY)
        github_soup_login = bs4.BeautifulSoup(github_html_login.text, 'html.parser')
        form_data_login = {
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
    except Exception as e:
        raise MsgException(e, 'Unable to HTTP-GET GitHub login data')

    try:  # 2nd request (submit the login form and grab some data needed for the OTP form)
        github_http_session.headers.update({
            'Content-Type': 'application/x-www-form-urlencoded',
        })
        github_html_twofactor = github_http_session.post(
            'https://github.com/session',
            data=parse.urlencode(form_data_login),
        )
        time.sleep(GITHUB_HTTP_DELAY)
        github_soup_twofactor = bs4.BeautifulSoup(github_html_twofactor.text, 'html.parser')
        form_data_otp = {
            'authenticity_token': github_soup_twofactor.find('input', {'name': 'authenticity_token'})['value'],
        }
    except Exception as e:
        raise MsgException(e, 'Unable to log in to GitHub (credentials)')

    try:  # 3rd request (submit the OTP form)
        form_data_otp.update({
            'otp': pyotp.TOTP(github_otp).now(),
        })
        github_http_session.post(
            'https://github.com/sessions/two-factor',
            data=parse.urlencode(form_data_otp),
        )
        time.sleep(GITHUB_HTTP_DELAY)
        github_http_session.headers.pop('Content-Type')
    except Exception as e:
        raise MsgException(e, 'Unable to log in to GitHub (OTP)')


def github_search_count(github_http_session, github_query_term, github_type):
    """Count search results."""
    try:
        github_html_count = github_http_session.get(
            f'https://github.com/search/count?q={parse.quote_plus(github_query_term)}&type={parse.quote_plus(github_type)}',
        )
        time.sleep(GITHUB_HTTP_DELAY)
        github_soup_count = bs4.BeautifulSoup(github_html_count.text, 'html.parser')
        github_count = github_soup_count.span.text
        return github_count
    except Exception as e:
        raise MsgException(e, 'Unable to count GitHub search results')


def github_search_retrieval(github_http_session, github_query_term, github_type):
    """Retrieve search results."""
    try:
        github_html_pages = github_http_session.get(
            f'https://github.com/search?o=desc&q={parse.quote_plus(github_query_term)}&type={parse.quote_plus(github_type)}',
        )
        time.sleep(GITHUB_HTTP_DELAY)
        github_soup_pages = bs4.BeautifulSoup(github_html_pages.text, 'html.parser')
        github_pages_tag = github_soup_pages.find('em', {'data-total-pages': True})
        github_pages = github_pages_tag['data-total-pages'] if github_pages_tag is not None else 1
        github_search_result = {}
        for github_page in range(int(github_pages)):
            github_html_page = github_http_session.get(
                f'https://github.com/search?o=desc&p={github_page + 1}&q={parse.quote_plus(github_query_term)}&type={parse.quote_plus(github_type)}',
            )
            time.sleep(GITHUB_HTTP_DELAY)
            github_soup_page = bs4.BeautifulSoup(github_html_page.text, 'html.parser')
            github_search_date = datetime.datetime.now().strftime('%F %T')
            for github_search_occurrence in github_soup_page.find_all('a', {'data-hydro-click': True}):
                github_search_result.update({
                    f'''https://github.com{github_search_occurrence['href']}''': f'{github_search_date}',
                })
        return github_search_result
    except Exception as e:
        raise MsgException(e, 'Unable to retrieve GitHub search results')


def github_logout(github_http_session):
    """Log out from GitHub (2 requests needed)."""
    try:  # 1st request (grab some data needed for the logout form)
        github_html_root = github_http_session.get(
            'https://github.com',
        )
        time.sleep(GITHUB_HTTP_DELAY)
        github_soup_root = bs4.BeautifulSoup(github_html_root.text, 'html.parser')
        form_data_logout = {
            'authenticity_token': github_soup_root.find('input', {'name': 'authenticity_token'})['value'],
        }
    except Exception as e:
        raise MsgException(e, 'Unable to HTTP-GET GitHub logout data')

    try:  # 2nd request (submit the logout form)
        github_http_session.headers.update({
            'Content-Type': 'application/x-www-form-urlencoded',
        })
        github_http_session.post(
            'https://github.com/logout',
            data=parse.urlencode(form_data_logout),
        )
        time.sleep(GITHUB_HTTP_DELAY)
        github_http_session.headers.pop('Content-Type')
    except Exception as e:
        raise MsgException(e, 'Unable to log out from GitHub')


def main():  # pylint: disable=C0116
    if len(sys.argv) != 3:
        print_usage()
        sys.exit(-1)
    try:
        github_username, github_password, github_otp, github_query_exact, github_query_terms, slack_webhook = load_config(sys.argv[1])
        if github_query_exact:
            github_query_terms = [f'"{github_query_term}"' for github_query_term in github_query_terms]
        github_http_session = requests.session()
        github_http_headers = {
            'User-Agent': 'Mozilla Firefox Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:53.0) Gecko/20100101 Firefox/53.0',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Encoding': 'gzip, deflate',
            'Accept-Language': 'en,es;q=0.5',
            'Connection': 'close',
            'Referer': 'https://github.com/',
        }
        github_http_session.headers.update(github_http_headers)
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
                print_info(f'{github_count} results while looking for {github_query_term} ({github_type})')
                if github_count != '0':
                    unseen_urls = save_output_return_unseen(github_search_retrieval(github_http_session, github_query_term, github_type), sys.argv[2])
                    if len(slack_webhook) != 0 and len(unseen_urls) != 0:
                        notify_slack(unseen_urls, slack_webhook)
    except MsgException as msg_exception:
        msg_exception.panic()
    except Exception as e:
        MsgException(e).panic()
    finally:
        try:
            github_logout(github_http_session)
            github_http_session.close()
        except Exception as e:
            MsgException(e).panic()
            sys.exit(-1)


if __name__ == '__main__':
    main()
