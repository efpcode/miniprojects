from requests import request
from hashlib import sha1
from sys import argv


def get_passwords():
    first_pass = True
    while True:
        try:
            if first_pass:
                passwords = argv[1:]
            empty = True if passwords else False
            assert empty is True, "No password(s) was/were entered!"

        except AssertionError as error:
            print(error)
            print(">>> Please enter a new password(s)")
            print(">>> Example of valid delimiters [Comma\\Space]\n>>> "
                  "pass123,secret,etc\n\tor\n>>> pass123 secret etc")
            passwords = input("Enter: ")
            if passwords:
                sep = "," if "," in passwords else " "
                passwords = passwords.split(sep)
            if passwords:
                first_pass = False
            continue
        else:
            return passwords


def str_to_sha1(password: str):
    password = password.encode("utf-8")
    hash_obj = sha1()
    hash_obj.update(password)
    hash_header, hash_tails = (hash_obj.hexdigest().upper()[:5],
                               hash_obj.hexdigest().upper()[5:])

    return hash_header, hash_tails


def get_api_response(hash_header: str):
    url = "https://api.pwnedpasswords.com/range/"
    get_url = "".join([url, hash_header])
    try:
        r = request(method="GET", url=get_url)
        if not r.status_code == 200:
            api_url = r"https://haveibeenpwned.com/API/"
            raise RuntimeError(f"Please read about the api link: {api_url}")
    except RuntimeError as error:
        print(error)
        return False
    else:
        return r


def breach_checker(pass_to_check: str = "password123"):
    hash_bytes, hash_bytes_tails = str_to_sha1(password=pass_to_check)
    r = get_api_response(hash_header=hash_bytes)

    if not r:
        return "API could not be called for."

    hash_tb = [i.split(":") for i in r.text.splitlines()]

    total_number = [
        times for hash_sec, times in [hash_val for hash_val in hash_tb] if
        hash_sec in hash_bytes_tails
    ]

    if not total_number:
        total_number = ["0"]

    total_number = int("".join(total_number))

    if total_number == 0:
        return f"{pass_to_check} is alright no breach found: {total_number}\n"
    else:
        return f"{pass_to_check} should be change, total number of breaches " \
               f"found: {total_number}\n"


def check_password():
    results = list()

    passwords = get_passwords()
    for secrete in passwords:
        results.append(breach_checker(secrete))
    return "".join(results)


if __name__ == "__main__":
    print(check_password())
    print(">>> Done!")

