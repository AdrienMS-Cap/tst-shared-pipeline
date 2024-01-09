import os
import re
import sys

def find_sensitive_info(file_path, sensitive_patterns):
    with open(file_path, 'r', encoding='utf-8') as file:
        print("Processing file: {}".format(file_path))
        content = file.read()
        for pattern in sensitive_patterns:
            matches = re.finditer(rf"{pattern}\s*:\s*(\S+)", content, re.IGNORECASE)
            for match in matches:
                line_number = content.count('\n', 0, match.start()) + 1
                print("ALERT - Sensitive information found in file: {}, Line {}".format(file_path, line_number))
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
