import requests
import hashlib
import sys



def request_api_data(query_char):
    url = 'https://api.pwnedpasswords.com/range/' + query_char
    response = requests.get(url)
    if response.status_code != 200:
        raise RuntimeError('Error fetching {}, check the API and try again'.format(response.status_code))
    return response

def get_password_leaks(hash, hash_to_check):
    hash = (line.split(':') for line in hash.text.splitlines())
    for hash, count in hash:
        if hash == hash_to_check:
            return count
    return 0


def pwned_api_check(password):
    #Check password if it exists in API response
    new_password = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
    first_phase, second_phase = new_password[:5], new_password[5:]
    response = request_api_data(first_phase)
    return get_password_leaks(response, second_phase)

def main(args):
    for passwords in args:
        count = pwned_api_check(passwords)
        if count:
            print '{} is compromised {} times, you should change your password immediately'.format(passwords,count)

        else:
            print '{} is strong password, keep going'.format(passwords)

    return 'Hope you loved our software'


main(sys.argv[1:])