import win32evtlog
from colorama import init, Fore, Style
from datetime import datetime
import os

init()

server = "localhost"
log_type = "Security"

event_dictionary = {
    4624: ("Successful Login", "LOW"),
    4625: ("Failed Login Attempt", "HIGH"),
    4672: ("Administrator Login", "MEDIUM"),
    4720: ("User Account Created", "HIGH"),
    4726: ("User Account Deleted", "MEDIUM"),
    5379: ("Credentials Read", "LOW"),
    5061: ("Cryptographic Operation", "LOW"),
    4798: ("User Group Membership Enumerated", "LOW")
}

try:
    log_handle = win32evtlog.OpenEventLog(server, log_type)
    total_records = win32evtlog.GetNumberOfEventLogRecords(log_handle)

    flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
    events = win32evtlog.ReadEventLog(log_handle, flags, 0)

    print("=" * 60)
    print("                 CyberWatch")
    print("         Windows Security Log Analyzer")
    print("=" * 60)

    print(f"\nTotal Security Events : {total_records}\n")
    print("Latest Security Events")
    print("-" * 60)

    count = 0
    successful_logins = 0
    failed_logins = 0
    admin_logins = 0
    credential_events = 0
    unknown_events = 0
    group_events = 0

    for event in events:
        event_id = event.EventID & 0xFFFF

        if event_id == 4624:
            successful_logins += 1
        elif event_id == 4625:
            failed_logins += 1
        elif event_id == 4672:
            admin_logins += 1
        elif event_id == 5379:
            credential_events += 1
        elif event_id == 4798:
            group_events += 1
        else:
            unknown_events += 1

        if event_id in event_dictionary:
            meaning, risk = event_dictionary[event_id]
        else:
            meaning, risk = "Unknown Event", "INFO"

        if risk == "HIGH":
            colour = Fore.RED
        elif risk == "MEDIUM":
            colour = Fore.YELLOW
        elif risk == "LOW":
            colour = Fore.GREEN
        else:
            colour = Fore.WHITE

        print(f"Event ID : {event_id}")
        print(f"Meaning  : {meaning}")
        print(f"Risk     : {colour}{risk}{Style.RESET_ALL}")
        print(f"Time     : {event.TimeGenerated}")
        print("-" * 60)

        count += 1
        if count == 1000:
            break

    # Overall Risk Calculation
    if failed_logins >= 5:
        overall_risk = "HIGH"
    elif admin_logins >= 3:
        overall_risk = "MEDIUM"
    else:
        overall_risk = "LOW"

    if overall_risk == "HIGH":
        overall_colour = Fore.RED
    elif overall_risk == "MEDIUM":
        overall_colour = Fore.YELLOW
    else:
        overall_colour = Fore.GREEN

        print("\n" + "=" * 40)
    print("CyberWatch Summary")
    print("=" * 40)
    print(f"Successful Logins : {successful_logins}")
    print(f"Failed Logins     : {failed_logins}")
    print(f"Admin Logins      : {admin_logins}")
    print(f"Credential Events : {credential_events}")
    print(f"Unknown Events    : {unknown_events}")
    print(f"Group Enumeration : {group_events}")

    print(f"\nOverall Risk Level : {overall_colour}{overall_risk}{Style.RESET_ALL}")

    # -------------------------
    # Generate Report
    # -------------------------

    report = f"""
==================================================
CyberWatch Report
==================================================

Generated On : {datetime.now().strftime("%d-%m-%Y %H:%M:%S")}

Total Security Events : {total_records}

Successful Logins : {successful_logins}
Failed Logins     : {failed_logins}
Admin Logins      : {admin_logins}
Credential Events : {credential_events}
Unknown Events    : {unknown_events}
Group Enumeration : {group_events}

Overall Risk Level : {overall_risk}

==================================================
End of Report
==================================================
"""

    report_path = os.path.join(os.getcwd(), "CyberWatch_Report.txt")

    with open(report_path, "w") as file:
        file.write(report)

    print(f"\nReport saved successfully!")
    print(f"Location: {report_path}")

except Exception as e:
    print("Error:", e)