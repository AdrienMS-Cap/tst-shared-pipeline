import os
import re
import sys

def find_sensitive_info(file_path, sensitive_patterns):
    with open(file_path, 'r', encoding='utf-8') as file:
        print("Processing file: {}".format(file_path))
        # Set the environment variable for the test report
        os.environ["TEST_REPORT"] = file_path
        content = file.read()
        for pattern in sensitive_patterns:
            if re.search(pattern, content, re.IGNORECASE):
                return True
    return False

def scan_for_sensitive_info(sensitive_patterns, script_file_path):
    error_found = False

    for root, dirs, files in os.walk("."):
        # Exclude the script file and directories/files that start with a dot
        dirs[:] = [d for d in dirs if not d.startswith('.') and not os.path.samefile(os.path.join(root, d), script_file_path)]
        files = [f for f in files if not f.startswith('.') and not os.path.samefile(os.path.join(root, f), script_file_path)]

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

    # Get the path of the script file
    script_file_path = os.path.abspath(__file__)

    error_found = scan_for_sensitive_info(sensitive_patterns, script_file_path)

    if error_found:
        sys.exit(1)
    else:
        print("No sensitive information found.")

if __name__ == "__main__":
    main()
