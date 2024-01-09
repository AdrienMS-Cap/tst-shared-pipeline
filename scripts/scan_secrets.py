import re
import os
import argparse
import sys

def scan_directory(path: str, script_path: str, ignore_files: list = []) -> None:
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
    secrets_found = []

    for root, dirs, files in os.walk(path):
        # Ignore directories that start with a dot
        dirs[:] = [d for d in dirs if not d.startswith('.')]
        
        for file in files:
            file_path = os.path.join(root, file)
            # Ignore specified files
            if os.path.abspath(file_path) == script_path or file in ignore_files:
                continue
            try:
                with open(file_path, 'r') as f:
                    print("Scanning file: {}.".format(file_path))
                    lines = f.readlines()
                    for i, line in enumerate(lines, 1):
                        for pattern in regex_patterns:
                            if pattern.search(line):
                                print("Possible sensitive data found in file: {}".format(file_path))
                                secrets_found.append((file_path, i))
            except Exception as e:
                print("Could not read file {}. Reason: {}".format(file_path, str(e)))

    if secrets_found:
        print("\nSummary of files with possible sensitive data:")
        for file_path, line_num in secrets_found:
            print(f"File: {file_path}, Line: {line_num}")
        sys.exit("Error: Secrets were found during the process.")

def main():
    """Main function to parse arguments and call the scan_directory function."""
    parser = argparse.ArgumentParser(description='Scan a directory for sensitive data.')
    parser.add_argument('path', type=str, help='The path to the directory you want to scan.')
    parser.add_argument('--ignore', nargs='+', default=[], help='List of files to ignore during the scan.')
    args = parser.parse_args()
    script_path = os.path.abspath(__file__)
    scan_directory(args.path, script_path, ignore_files=args.ignore)

if __name__ == "__main__":
    main()
