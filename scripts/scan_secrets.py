import os
import re
import sys
from gitignore_parser import parse_gitignore

def find_sensitive_info(file_path, sensitive_patterns):
    with open(file_path, 'r', encoding='utf-8') as file:
        print("Processing file: {}".format(file_path))
        content = file.read()
        for pattern in sensitive_patterns:
            if re.search(pattern, content, re.IGNORECASE):
                return True
    return False

def scan_for_sensitive_info(sensitive_patterns, gitignore_parser):
    error_found = False

    for root, dirs, files in os.walk("."):
        # Filter out files and directories ignored by .gitignore
        dirs[:] = [d for d in dirs if not gitignore_parser(root, d)]
        files = [f for f in files if not gitignore_parser(root, f)]

        for file in files:
            file_path = os.path.join(root, file)
            if find_sensitive_info(file_path, sensitive_patterns):
                print(f"Sensitive information found in file: {file_path}")
                error_found = True

    return error_found

def main():
    sensitive_patterns = [
        "password",
        "api",
        "token",
        "secret",
        "key",
        "credentials",
        "access_key",
        "secret_key",
        "auth_token",
        "private_key",
        "client_secret",
        "db_password",
        "connection_string",
        "oauth",
        "ssh-rsa",
    ]

    # Load .gitignore and create a parser
    gitignore_path = os.path.join(os.getcwd(), '.gitignore')
    if os.path.exists(gitignore_path):
        gitignore_parser = parse_gitignore(gitignore_path)
    else:
        gitignore_parser = lambda x, y: False


    error_found = scan_for_sensitive_info(sensitive_patterns, gitignore_parser)

    if error_found:
        sys.exit(1)
    else:
        print("No sensitive information found.")

if __name__ == "__main__":
    main()
