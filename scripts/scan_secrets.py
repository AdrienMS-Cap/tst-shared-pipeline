import re
import os
import argparse

def scan_directory(path: str) -> None:
    """Scan a directory for sensitive data."""
    sensitive_patterns = [
        "password",
        "pwd",
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

    regex_patterns = [re.compile(rf'{pattern}.\s?[a-zA-Z0-9]+') for pattern in sensitive_patterns]

    for root, dirs, files in os.walk(path):
        for file in files:
            file_path = os.path.join(root, file)
            try:
                with open(file_path, 'r') as f:
                    print("Scanning file: {}.".format(file_path))
                    contents = f.read()
                    for pattern in regex_patterns:
                        if pattern.search(contents):
                            print("Possible sensitive data found in file: {}".format(file_path))
            except Exception as e:
                print("Could not read file {}. Reason: {}".format(file_path, str(e)))

def main():
    """Main function to parse arguments and call the scan_directory function."""
    parser = argparse.ArgumentParser(description='Scan a directory for sensitive data.')
    parser.add_argument('path', type=str, help='The path to the directory you want to scan.')
    args = parser.parse_args()
    scan_directory(args.path)

if __name__ == "__main__":
    main()
