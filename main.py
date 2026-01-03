import requests
from urllib.parse import urlparse
#import re

#target url
target_url =  input("Enter the targeted URL: ").strip()

parsed_url = urlparse(target_url)
#domain = parsed_url.netloc

#headers to check
required_headers = {
    "Content-Security-Policy": True,
    "X-Content-Type-Options": True,
    "X-Frame-Options": True,
    "X-XSS-Protection": True
}


#report
vulnerability_report = []

# scan for missing headers

try:
    response = requests.get(target_url)
    response.raise_for_status()

    for header in required_headers:
        if header not in response.headers:
            vulnerability_report.append(f"Missing Header: {header}")
except requests.RequestException as e:
    print(f"Error fetching URL: {e}")
    exit()


#xss testing
xss_payload = "<script>alert('1')</script>"
xss_test_url = target_url + xss_payload
try:
    xss_response = requests.get(xss_test_url)
    if xss_payload in xss_response.text:
        vulnerability_report.append("XSS Vulnerability Detected")

except requests.RequestException as e:
    print(f"Error during XSS test: {e}")


#SQLI test
sqli_payload = "' OR '1'='1"
sql_i_test_url = target_url + sqli_payload

sql_errors = [
    "sql syntax",
    "mysql",
    "syntax error",
    "unclosed quotation"
]
try:
    sql_i_response = requests.get(sql_i_test_url)
    for error in sql_i_response.text.lower():
        vulnerability_report.append("SQL Vulnerabiltiy Detected")
        break

except requests.RequestException as e:
    print(f"Error during SQLI test: {e}")

#report
print("\n=== Vulnerability Report ===")
if vulnerability_report:
    for vuln in vulnerability_report:
        print(f"[!] {vuln}")

else:
    print("No vulnerability detected")
