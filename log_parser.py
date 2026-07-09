#!/usr/bin/env python3

"""
- log_parser.py
- This program parses Linux auth.log files to classify security events with severity, and then outputs results to either JSON or CSV 
- I built this project as part of my Cybersecurity portfolio.
"""

import re # Regular Expressions - This is used to search for patterns inside the logs.
import json # JSON - This is used to convert pythons dicts/lists into a JSON file.
import csv # CSV - This is used to write to a CSV file, for better compatibility.
import argparse # - This is used to accept command line arguements.
import sys # - This is used for access to system level things like exiting the script cleanly when a critical error happens.

# --------------------------------------------------------------

TIMESTAMP_PATTERN = re.compile(r'(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})') # These REGEX patterns are for parsing timestamps, 
IP_PATTERN = re.compile(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})')         # IP addresses, 
USER_PATTERN = re.compile(r'(?:for|user)\s+(\w+)')                       # Usernames, 
PORT_PATTERN = re.compile(r'port\s+(\d+)')                               # and Ports out of the ingested logs.

# --------------------------------------------------------------

FAILED_KEYWORDS = [                # These keywords stored in the lists is common failure keywords that the REGEX patterns use to classify an event.
    "Failed password",
    "authentication failure",
    "Invalid user",
    "FAILED",
]

SUCCESS_KEYWORDS = [
    "Accepted password",
    "Accepted publickey",
    "session opened",
    "NEW SESSION",
]

SUDO_KEYWORDS = [
    "sudo",
    "COMMAND",
]

SYSTEM_KEYWORDS = [
    "session closed",
    "Disconnected",
    "cron",
    "pam_unix",
]

# --------------------------------------------------------------

def classify_event(line):               # Defining the function 'classify_event' is used to determine what happened, the order is made through priority, 
    for keyword in FAILED_KEYWORDS:     # keeping failed events as a priority, and system events as least priority. The function looks through the keyword lists above 
        if keyword in line:             # and the first match is what the event is classified as. If no keywords match, 'Unknown' is returned.
            return "Failed Login"

    for keyword in SUCCESS_KEYWORDS:
        if keyword in line:
            return "Successful Login"

    for keyword in SUDO_KEYWORDS:
        if keyword in line:
            return "Privilege Escalation"

    for keyword in SYSTEM_KEYWORDS:
        if keyword in line:
            return "System Event"

    return "Unknown"

# --------------------------------------------------------------

def assign_severity(event_type):                # Defining the function 'assign_severity' is used to determine the severity of the event.
    severity_map = {                            # A dict is used here to directly map each of the previously returned classified events into a severity level.
        "Failed Login":         "HIGH",
        "Privilege Escalation": "HIGH",         
        "Successful Login":     "MEDIUM",
        "System Event":         "LOW",
        "Unknown":              "INFO",
    }
    return severity_map.get(event_type, "INFO")            # .get() returns the value of the matched severity level to the event. 
                                                           # .get() is used over a direct lookup in the case that no match is found, it returns 'INFO' instead of crashing.
# --------------------------------------------------------------

def parse_line(line, line_number):                                              # This defined function is used to parse the ingested file. 
    line = line.strip()                                                         # It uses all REGEX patterns to extract the useful information
    if not line:                                                                # from the log file and insert it into a dict.
        return None                                                             #  .search() is used in each variable assignment to find the Timestamp, IP, Username, and Port in each string

    timestamp_match = TIMESTAMP_PATTERN.search(line)                            
    timestamp = timestamp_match.group(1) if timestamp_match else "Unknown"

    ip_match = IP_PATTERN.search(line)
    source_ip = ip_match.group(1) if ip_match else None

    port_match = PORT_PATTERN.search(line)
    port = port_match.group(1) if port_match else None

    user_match = USER_PATTERN.search(line)
    username = user_match.group(1) if user_match else None

    event_type = classify_event(line)
    severity = assign_severity(event_type)

    return {
        "line_number": line_number,
        "timestamp":   timestamp,
        "source_ip":   source_ip,
        "port":        port,
        "username":    username,
        "event_type":  event_type,
        "severity":    severity,
        "raw":         line,
    }

# --------------------------------------------------------------
                                                                                    # This function opens a log file, and parses each line, then returning a list of parsed events.
def parse_log_file(log_path):                                                       # The 'log_path' parameter is the path to the log file to parse.
    parsed_events = []                                                              # 'parsed_events' sets up an empty list that soon collects each parsed entry.
    errors = 0                                                                      # A counter for blank or unparsable lines that will be later used in summary report.

    print(f"[*] Opening log file: {log_path}")

    try:
        with open(log_path, 'r', encoding='utf-8', errors='replace') as f:          # Opens the file, enumerates the lines starting from 1,
            for line_number, line in enumerate(f, start=1):                         # and for each line in the file 'parse_line()' runs and returns useful, parsed information;
                parsed = parse_line(line, line_number)                              # which is then appended to the 'parsed_events' list.
                if parsed:                                                          # If 'None' is returned, the error counter adds 1.
                    parsed_events.append(parsed)
                else:
                    errors += 1

    except FileNotFoundError:                                                       # This section is error handling using try/except blocks. If there is a FileNotFoundError or
        print(f"[ERROR] Log file not found: {log_path}")                            # PermissionError, a more useful, human readable message exits.
        sys.exit(1)

    except PermissionError:
        print(f"[ERROR] Permission denied reading: {log_path}")
        print("[TIP] Try running with: sudo python3 log_parser.py ...")
        sys.exit(1)

    print(f"[*] Parsed {len(parsed_events)} events ({errors} blank/skipped lines)") 
    return parsed_events                                                            # After the function completes, the list containing all parsed events is later used for main() function.

# --------------------------------------------------------------

def write_json(events, output_path):                                # This function uses the 'events' parameter and 'output_path' parameter
    with open(output_path, 'w', encoding='utf-8') as f:             # to write the parsed events to a JSON file.
        json.dump(events, f, indent=4, default=str)                 # JSON is used as the file output because Splunk and most SIEMs ingest JSON natively. 
                                                                    
    print(f"[+] JSON output saved to: {output_path}")

# --------------------------------------------------------------

def write_csv(events, output_path):                                 # This function is used as an alternative to writing to a JSON file.
    if not events:                                                  # The same parameters as 'write_json' are used to write the parsed events to a CSV file.
        print("[!] No events to write to CSV.")                     # CSV is also included in this lab because analysts pull CSV data into Excel often, 
        return                                                      # it's also easy to import other tools.

    fieldnames = list(events[0].keys())

    with open(output_path, 'w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(events)

    print(f"[+] CSV output saved to: {output_path}")

# -------------------------------------------------------------- 

def print_summary(events):                                      # This function prints a general overview of total events, 
    if not events:                                              # and counts of each event type, 
        print("[!] No events were parsed.")                     # and counts of each severity levels.
        return

    print("\n" + "="*50)                                        
    print("         PARSE SUMMARY")
    print("="*50)
    print(f"  Total events parsed : {len(events)}")

    type_counts = {}
    severity_counts = {}

    for event in events:
        et = event["event_type"]
        type_counts[et] = type_counts.get(et, 0) + 1

        sv = event["severity"]
        severity_counts[sv] = severity_counts.get(sv, 0) + 1

    print("\n  --- By Event Type ---")                         #Counts distinct event types and prints to console
    for event_type, count in sorted(type_counts.items()):
        print(f"  {event_type:<25} {count}")

    print("\n  --- By Severity ---")                           #Counts distinct severity types and prints to console
    for severity, count in sorted(severity_counts.items()):
        print(f"  {severity:<10} {count}")

    print("="*50 + "\n")

# -------------------------------------------------------------- 

def generate_sample_log(output_path="sample_auth.log"):                                                                             # A list of sample auth.log entries that will be used if there is no input
    sample_lines = [
        "Jun 26 09:01:12 ubuntu-server sshd[1101]: Failed password for root from 203.0.113.42 port 51234 ssh2",
        "Jun 26 09:01:15 ubuntu-server sshd[1101]: Failed password for root from 203.0.113.42 port 51235 ssh2",
        "Jun 26 09:01:18 ubuntu-server sshd[1101]: Failed password for root from 203.0.113.42 port 51236 ssh2",
        "Jun 26 09:01:20 ubuntu-server sshd[1101]: Failed password for admin from 203.0.113.42 port 51237 ssh2",
        "Jun 26 09:01:22 ubuntu-server sshd[1101]: Invalid user testuser from 198.51.100.77 port 44321 ssh2",
        "Jun 26 09:05:44 ubuntu-server sshd[1102]: Accepted password for ibrahim from 192.168.1.10 port 52101 ssh2",
        "Jun 26 09:05:44 ubuntu-server sshd[1102]: pam_unix(sshd:session): session opened for user ibrahim by (uid=0)",
        "Jun 26 09:10:01 ubuntu-server sudo:  ibrahim : TTY=pts/0 ; PWD=/home/ibrahim ; USER=root ; COMMAND=/bin/cat /etc/shadow",
        "Jun 26 09:15:33 ubuntu-server sshd[1103]: Accepted publickey for ibrahim from 192.168.1.10 port 52200 ssh2",
        "Jun 26 09:20:00 ubuntu-server CRON[1234]: pam_unix(cron:session): session opened for user root by (uid=0)",
        "Jun 26 09:20:01 ubuntu-server CRON[1234]: pam_unix(cron:session): session closed for user root",
        "Jun 26 09:25:10 ubuntu-server sshd[1105]: Disconnected from user ibrahim 192.168.1.10 port 52101",
        "Jun 26 09:30:05 ubuntu-server sshd[1106]: Failed password for invalid user oracle from 45.33.32.156 port 39812 ssh2",
        "Jun 26 09:30:06 ubuntu-server sshd[1106]: Failed password for invalid user postgres from 45.33.32.156 port 39813 ssh2",
        "Jun 26 09:45:00 ubuntu-server sshd[1107]: authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost=10.0.0.99",
        "",                                                                                                                         #Blank line that is used to test system
        "Jun 26 10:00:00 ubuntu-server systemd-logind[900]: NEW SESSION 55 OF USER ibrahim",
    ]

    with open(output_path, 'w') as f:
        f.write('\n'.join(sample_lines))

    print(f"[+] Sample log file created: {output_path}")
    return output_path

# -------------------------------------------------------------- 

def main():
    parser = argparse.ArgumentParser(                                                   # argparse is used here to let my script understand flags I type after the filename. 
        description="Linux Auth Log Parser — extracts security events into JSON/CSV",
        epilog="Example: python3 log_parser.py --log /var/log/auth.log --csv"
    )

    parser.add_argument(                                                                # '--log' flag is used to specify which log file to parse.
        "--log",
        type=str,
        help="Path to the auth log file (e.g., /var/log/auth.log)."
    )

    parser.add_argument(                                                                # '--output' flag is used to specify where to save the JSON file.
        "--output",
        type=str,
        default="parsed_logs.json",                                                     # If no file name is specified, this defaults the filename.
        help="Output JSON filename (default: parsed_logs.json)"
    )

    parser.add_argument(                                                                # '--csv' flag is created as a boolean swtich, writing '--csv' sets it to True, without it defaults to False.
        "--csv",
        action="store_true",
        help="Also export results as a CSV file"
    )

    parser.add_argument(                                                                # '--sample' flag creates a sample log and exits
        "--sample",
        action="store_true",
        help="Generate a sample auth.log file for testing and exit"
    )

    args = parser.parse_args()                                                          # Parse the typed arguements

    if args.sample:
        generate_sample_log()
        sys.exit(0)                                                                     # Exits after generating sample.

    if args.log:                                                                        # This is used to determine the log file. If no file is specified, a generated sample will be used.
        log_path = args.log
    else:
        print("[*] No log file specified. Generating sample log for demo...")
        log_path = generate_sample_log()

    events = parse_log_file(log_path)                       # Parse the log file

    write_json(events, args.output)                         # Write to a JSON file

    if args.csv:                                            # Optional CSV output
        csv_output = args.output.replace(".json", ".csv")
        write_csv(events, csv_output)

    print_summary(events)                                   # Prints summary to terminal


if __name__ == "__main__":
    main()
