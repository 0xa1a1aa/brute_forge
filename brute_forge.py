import requests
import argparse
import re
from urllib.parse import urlparse


def brute(verbose, url, login_request, headers, allow_redirects, proxies, username, password, token_regex, status_str, status_str_neg):
    csrf_token = None
    cookies = None

    # Issue a GET request and retrieve the CSRF-token
    if verbose:
        print(f"[*] Requesting {url} for CSRF-token...")
    with requests.get(url, headers=headers, allow_redirects=allow_redirects, proxies=proxies) as response:
        body = response.text
        cookies = response.cookies

        # Search the CSRF-token in the response body
        match = re.search(token_regex, body)
        if match:
            csrf_token = match.group(1)
            if verbose:
                print(f"[+] Found CSRF-token: {csrf_token}")
        else: # Abort if we can"t find the CSRF-token
            print(f"[-] No CSRF-token found. Login request for username: '{username}' and password '{password}' was cancelled. Aborting...")
            return False

    # Replace placeholders in HTTP headers
    for k, v in login_request["headers"].items():
        if "^CSRF^" in v:
            login_request["headers"][k] = v.replace("^CSRF^", csrf_token)

    # Replace placeholders in HTTP body
    request_body = login_request["body"].replace("^USER^", username).replace("^PASS^", password).replace("^CSRF^", csrf_token)

    # Issue a login request with the CSRF-token
    if verbose:
        print(f"[*] Issue login request to {login_request['url']} - Username: {username}, Password: {password}")
    success = False
    with requests.request(
        login_request["method"],
        login_request["url"],
        headers=login_request["headers"],
        cookies=cookies,
        data=request_body,
        allow_redirects=allow_redirects,
        proxies=proxies
    ) as response:
        body = response.text

        if status_str_neg:
            # If fail is not in the body => correct creds
            if not status_str in body:
                success = True
        else:
            # If success is in the body => correct creds
            if status_str in body:
                success = True

    if success:
        print("==========[ Success ]==========")
        print(f"Username: {username}")
        print(f"Password: {password}")
        return True

    return False


def main(args):
    # Setup usernames/passwords
    usernames = [args.username]
    if args.username_file:
        usernames = open(args.username_file, "r")
 
    passwords = [args.password]
    if args.password_file:
        passwords = open(args.password_file, "r")
    
    # Parse login request from file
    login_request = {}
    with open(args.request, "r") as f:
        request = f.read()

        headers, body = request.split("\n\n", 1)
        first_line, headers = headers.split("\n", 1)
        method, uri, http = first_line.split(" ", 2)
        
        host = None
        headers_dict = {}
        for header in headers.split("\n"):
            key, value = header.split(": ", 1)
            if key != "Host":
                headers_dict[key] = value
            else:
                host = value

        # The protocol for the login request is taken from the supplied url
        proto = urlparse(args.url).scheme
        
        login_request["url"] = proto + "://" + host + uri
        login_request["method"] = method
        login_request["headers"] = headers_dict
        login_request["body"] = body

    # Use custom headers
    headers = None
    if args.headers:
        headers = json.loads(args.headers)

    # Set proxy
    proxies = {"http": args.proxy}

    success = False
    for username in usernames:
        for password in passwords:
            success = brute(
                args.verbose,
                args.url,
                login_request,
                headers,
                args.allow_redirects,
                proxies,
                username.strip(),
                password.strip(),
                args.token_regex,
                args.fail or args.success,
                True if args.fail else False,
            )
            if success:
                break
        if success:
            break

        # Seek to beginning of password file
        passwords.seek(0)


    # Cleanup
    if args.username_file:
        usernames.close()
    if args.password_file:
        passwords.close()


def parse_args():
    parser = argparse.ArgumentParser(prog="brute_forge", description="brute-force http logins protected with CSRF-tokens")
    parser.add_argument("-u", "--url", help="URL of login form", required=True)
    parser.add_argument("-r", "--request", help="File containing the login request (likely a POST request). Placeholders: username=^USER^, password=^PASS^, CSRF-token=^CSRF^", required=True)
    parser.add_argument("-H", "--headers", help="HTTP headers as JSON string. Placeholders: ^CSRF^. Example: {'x-header1': 'yep', 'x-csrf-token': '^CSRF^'}")
    parser.add_argument("-t", "--token-regex", help="Regex for CSRF-token. The CSRF-token is set as the first group of a potential match. Example: 'token=\"(.*?)\"'", required=True)
    parser.add_argument("-R", "--allow-redirects", help="Allow redirects", action="store_true")
    parser.add_argument("--proxy", help="Proxy URL")
    parser.add_argument("-v", "--verbose", help="Verbose", action="store_true")

    username_group = parser.add_mutually_exclusive_group()
    username_group.add_argument("-l", "--username", help="Single username for login")
    username_group.add_argument("-L", "--username-file", help="File containing usernames (one per line)")
    
    password_group = parser.add_mutually_exclusive_group()
    password_group.add_argument("-p", "--password", help="Single password for login")
    password_group.add_argument("-P", "--password-file", help="File containing passwords (one per line)")

    status_group = parser.add_mutually_exclusive_group()
    status_group.add_argument("-f", "--fail", help="String that indicates a failed login attempt")
    status_group.add_argument("-s", "--success", help="String that indicates a successful login attempt")

    return parser.parse_args()


if __name__ == "__main__":
    main(parse_args())
