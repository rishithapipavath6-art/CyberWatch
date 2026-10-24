import os
from datetime import datetime, timedelta

import win32evtlog
from colorama import Fore, Style, init

init()

SERVER = "localhost"
LOG_TYPE = "Security"
HOURS_TO_ANALYZE = 24
MAX_EVENTS_TO_DISPLAY = 30

event_dictionary = {
    4624: ("Successful Login", "LOW"),
    4625: ("Failed Login Attempt", "HIGH"),
    4672: ("Administrator Privileges Assigned", "MEDIUM"),
    4720: ("User Account Created", "HIGH"),
    4726: ("User Account Deleted", "MEDIUM"),
    5379: ("Credentials Read", "LOW"),
    5061: ("Cryptographic Operation", "LOW"),
    4798: ("User Group Membership Enumerated", "LOW"),
}


def get_colour(risk):
    if risk == "HIGH":
        return Fore.RED
    if risk == "MEDIUM":
        return Fore.YELLOW
    if risk == "LOW":
        return Fore.GREEN
    return Fore.WHITE


try:
    log_handle = win32evtlog.OpenEventLog(SERVER, LOG_TYPE)
    total_records = win32evtlog.GetNumberOfEventLogRecords(log_handle)

    flags = (
        win32evtlog.EVENTLOG_BACKWARDS_READ
        | win32evtlog.EVENTLOG_SEQUENTIAL_READ
    )

    cutoff_time = datetime.now() - timedelta(hours=HOURS_TO_ANALYZE)

    events_analyzed = 0
    events_displayed = 0

    successful_logins = 0
    failed_logins = 0
    admin_logins = 0
    credential_events = 0
    group_events = 0
    account_created = 0
    account_deleted = 0
    cryptographic_events = 0
    unknown_events = 0

    print("=" * 64)
    print("                         CyberWatch")
    print("               Windows Security Log Analyzer")
    print("=" * 64)

    print(f"\nTotal events stored in Security Log : {total_records}")
    print(f"Analysis period                     : Last {HOURS_TO_ANALYZE} hours")
    print(f"Starting from                       : {cutoff_time}")
    print("\nLatest events from the selected period")
    print("-" * 64)

    reached_cutoff = False

    while not reached_cutoff:
        events = win32evtlog.ReadEventLog(log_handle, flags, 0)

        if not events:
            break

        for event in events:
            event_time = event.TimeGenerated

            if event_time < cutoff_time:
                reached_cutoff = True
                break

            event_id = event.EventID & 0xFFFF
            events_analyzed += 1

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
            elif event_id == 4720:
                account_created += 1
            elif event_id == 4726:
                account_deleted += 1
            elif event_id == 5061:
                cryptographic_events += 1
            else:
                unknown_events += 1

            meaning, risk = event_dictionary.get(
                event_id,
                ("Unclassified Windows Event", "INFO"),
            )

            # Display only the first 30 events so the terminal stays readable.
            if events_displayed < MAX_EVENTS_TO_DISPLAY:
                colour = get_colour(risk)

                print(f"Event ID : {event_id}")
                print(f"Meaning  : {meaning}")
                print(f"Risk     : {colour}{risk}{Style.RESET_ALL}")
                print(f"Time     : {event_time}")
                print("-" * 64)

                events_displayed += 1

    # Calculate overall risk.
    if failed_logins >= 5 or account_created >= 1:
        overall_risk = "HIGH"
    elif admin_logins >= 3 or account_deleted >= 1:
        overall_risk = "MEDIUM"
    else:
        overall_risk = "LOW"

    overall_colour = get_colour(overall_risk)

    print("\n" + "=" * 48)
    print("CyberWatch – Last 24 Hours Summary")
    print("=" * 48)
    print(f"Events Analysed       : {events_analyzed}")
    print(f"Successful Logins     : {successful_logins}")
    print(f"Failed Logins         : {failed_logins}")
    print(f"Admin Events          : {admin_logins}")
    print(f"Credential Events     : {credential_events}")
    print(f"Group Enumeration     : {group_events}")
    print(f"Accounts Created      : {account_created}")
    print(f"Accounts Deleted      : {account_deleted}")
    print(f"Cryptographic Events  : {cryptographic_events}")
    print(f"Other Events          : {unknown_events}")

    print(
        f"\nOverall Risk Level    : "
        f"{overall_colour}{overall_risk}{Style.RESET_ALL}"
    )

    # Recommendations
    recommendations = []

    if failed_logins >= 5:
        recommendations.append(
            "Investigate repeated failed login attempts."
        )

    if admin_logins >= 3:
        recommendations.append(
            "Review administrator activity for unexpected access."
        )

    if account_created >= 1:
        recommendations.append(
            "Verify that all newly created user accounts are authorised."
        )

    if account_deleted >= 1:
        recommendations.append(
            "Confirm that deleted user accounts were removed intentionally."
        )

    if not recommendations:
        recommendations.append(
            "No major warning signs were detected in the selected period."
        )

    print("\nRecommendations")
    print("-" * 48)

    for recommendation in recommendations:
        print(f"- {recommendation}")

    # Create report
    report_lines = [
        "=" * 55,
        "CyberWatch – Windows Security Report",
        "=" * 55,
        "",
        f"Generated on          : {datetime.now():%d-%m-%Y %H:%M:%S}",
        f"Analysis period       : Last {HOURS_TO_ANALYZE} hours",
        f"Events analysed       : {events_analyzed}",
        "",
        f"Successful logins     : {successful_logins}",
        f"Failed logins         : {failed_logins}",
        f"Admin events          : {admin_logins}",
        f"Credential events     : {credential_events}",
        f"Group enumeration     : {group_events}",
        f"Accounts created      : {account_created}",
        f"Accounts deleted      : {account_deleted}",
        f"Cryptographic events  : {cryptographic_events}",
        f"Other events          : {unknown_events}",
        "",
        f"Overall risk level    : {overall_risk}",
        "",
        "Recommendations:",
    ]

    for recommendation in recommendations:
        report_lines.append(f"- {recommendation}")

    report_lines.extend(
        [
            "",
            "=" * 55,
            "End of Report",
            "=" * 55,
        ]
    )

    reports_folder = os.path.join(os.getcwd(), "Reports")
    os.makedirs(reports_folder, exist_ok=True)

    report_filename = (
        f"CyberWatch_Report_{datetime.now():%Y-%m-%d_%H-%M-%S}.txt"
    )
    report_path = os.path.join(reports_folder, report_filename)

    with open(report_path, "w", encoding="utf-8") as report_file:
        report_file.write("\n".join(report_lines))

    print("\nReport saved successfully!")
    print(f"Location: {report_path}")

    win32evtlog.CloseEventLog(log_handle)

except PermissionError:
    print(
        f"{Fore.RED}Permission denied. Run VS Code as Administrator."
        f"{Style.RESET_ALL}"
    )

except Exception as error:
    print(f"{Fore.RED}Error: {error}{Style.RESET_ALL}")