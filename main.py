import requests
import hashlib
from sys import argv, exit


def request_api_data(query_char):
    # api call where we forward 1st 5 digits of out sha1 hash
    url = 'https://api.pwnedpasswords.com/range/' + query_char
    response = requests.get(url)
    if response.status_code != 200:
        raise RuntimeError(
            f'Error fetching: {response.status_code}, check the api and try again')
    # return us the tail of hash x > 5 > response
    return response


def get_password_leak_count(hashes, hash_to_check):
    # hashes.text => contains hash and count, how much time someone cracked it
    hashes = (line.split(':') for line in hashes.text.splitlines())
    # hashes => is now an generator object which we can iterate over
    for h, c in hashes:
        # compare our sha1 tail and their(response) tail
        if h == hash_to_check:
            return c
    return 0


def pwned_api_check(password):
    # create sha1 hash
    sha1pass = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
    # separate 5char for api request and tail to compare reponse
    first5_charr, tail = sha1pass[:5], sha1pass[5:]
    # we get api response
    response = request_api_data(first5_charr)
    # we return api response and our tail to get compared
    return get_password_leak_count(response, tail)


def main(args):
    for password in args:
        count = pwned_api_check(password)
        if count:
            print(
                f'{password} was found {count} times.. you should change your password!')
        else:
            print(f'{password} was not found. That\'s a good password!')


if __name__ == '__main__':
    exit(main(argv[1:]))
