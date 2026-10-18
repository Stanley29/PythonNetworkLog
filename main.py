from datetime import datetime

LOG_FILE = "network_log.txt"
REPORT_FILE = "report.txt"


def analyze_log():
    try:
        file = open(LOG_FILE, "r", encoding="utf-8-sig")
        lines = file.readlines()
        file.close()
    except FileNotFoundError:
        print("File network_log.txt was not found.")
        return None
    except OSError as error:
        print("Error reading file:", error)
        return None

    success = 0
    failed = 0
    invalid = 0

    failed_ips = {}
    ports = {}

    for line in lines:
        parts = line.strip().split(";")

        if len(parts) != 4:
            invalid += 1
            continue

        date_time = parts[0].strip()
        ip = parts[1].strip()
        status = parts[2].strip()
        port_text = parts[3].strip()

        if not date_time or not ip:
            invalid += 1
            continue

        try:
            datetime.strptime(date_time, "%Y-%m-%d %H:%M:%S")
        except ValueError:
            invalid += 1
            continue

        if status != "SUCCESS" and status != "FAILED":
            invalid += 1
            continue

        try:
            port = int(port_text)
        except ValueError:
            invalid += 1
            continue

        if port < 1 or port > 65535:
            invalid += 1
            continue

        if status == "SUCCESS":
            success += 1
        else:
            failed += 1

            if ip in failed_ips:
                failed_ips[ip] += 1
            else:
                failed_ips[ip] = 1

        if port in ports:
            ports[port] += 1
        else:
            ports[port] = 1

    total = success + failed

    if total > 0:
        percentage = failed / total * 100
    else:
        percentage = 0

    most_failed_ip = ""
    most_failed_count = 0

    for ip in failed_ips:
        if failed_ips[ip] > most_failed_count:
            most_failed_ip = ip
            most_failed_count = failed_ips[ip]

    most_popular_port = ""
    most_popular_count = 0

    for port in ports:
        if ports[port] > most_popular_count:
            most_popular_port = port
            most_popular_count = ports[port]

    suspicious_ips = {}

    for ip in failed_ips:
        if failed_ips[ip] >= 3:
            suspicious_ips[ip] = failed_ips[ip]

    stats = {
        "total": total,
        "invalid": invalid,
        "success": success,
        "failed": failed,
        "percentage": percentage,
        "failed_ips": failed_ips,
        "ports": ports,
        "most_failed_ip": most_failed_ip,
        "most_failed_count": most_failed_count,
        "most_popular_port": most_popular_port,
        "most_popular_count": most_popular_count,
        "suspicious_ips": suspicious_ips
    }

    print("Log analysis completed.")
    return stats


def show_statistics(stats):
    print("\n===== STATISTICS =====")
    print("Valid records:", stats["total"])
    print("Invalid records:", stats["invalid"])
    print("Successful connections:", stats["success"])
    print("Failed connections:", stats["failed"])
    print("Failure percentage:", round(stats["percentage"], 2), "%")

    if stats["most_failed_ip"] == "":
        print("IP with most failed connections: none")
    else:
        print(
            "IP with most failed connections:",
            stats["most_failed_ip"],
            "-",
            stats["most_failed_count"],
            "attempts"
        )

    if stats["most_popular_port"] == "":
        print("Most popular port: none")
    else:
        print(
            "Most popular port:",
            stats["most_popular_port"],
            "-",
            stats["most_popular_count"],
            "attempts"
        )


def show_suspicious_ips(stats):
    print("\n===== SUSPICIOUS IP ADDRESSES =====")

    if len(stats["suspicious_ips"]) == 0:
        print("No suspicious IP addresses found.")
    else:
        for ip in stats["suspicious_ips"]:
            print(ip, "-", stats["suspicious_ips"][ip], "failed attempts")


def save_report(stats):
    report = []

    report.append("===== NETWORK LOG REPORT =====")
    report.append("Report date: " + datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
    report.append("")
    report.append("Valid records: " + str(stats["total"]))
    report.append("Invalid records: " + str(stats["invalid"]))
    report.append("Successful connections: " + str(stats["success"]))
    report.append("Failed connections: " + str(stats["failed"]))
    report.append("Failure percentage: " + str(round(stats["percentage"], 2)) + "%")

    if stats["most_failed_ip"] == "":
        report.append("IP with most failed connections: none")
    else:
        report.append(
            "IP with most failed connections: "
            + stats["most_failed_ip"]
            + " ("
            + str(stats["most_failed_count"])
            + " attempts)"
        )

    if stats["most_popular_port"] == "":
        report.append("Most popular port: none")
    else:
        report.append(
            "Most popular port: "
            + str(stats["most_popular_port"])
            + " ("
            + str(stats["most_popular_count"])
            + " attempts)"
        )

    report.append("")
    report.append("Suspicious IP addresses:")

    if len(stats["suspicious_ips"]) == 0:
        report.append("None")
    else:
        for ip in stats["suspicious_ips"]:
            report.append(
                ip + " - " + str(stats["suspicious_ips"][ip]) + " failed attempts"
            )

    try:
        file = open(REPORT_FILE, "w", encoding="utf-8")
        file.write("\n".join(report) + "\n")
        file.close()
        print("Report saved to report.txt.")
    except OSError as error:
        print("Error saving report:", error)


def main():
    stats = None

    while True:
        print("\n===== NETWORK LOG ANALYZER =====")
        print("1. Analyze log")
        print("2. Show statistics")
        print("3. Show suspicious IP addresses")
        print("4. Save report")
        print("0. Exit")

        try:
            choice = input("Choose an option: ").strip()
        except (EOFError, KeyboardInterrupt):
            print("\nGoodbye!")
            break

        if choice == "1":
            stats = analyze_log()

        elif choice == "2":
            if stats is None:
                print("Please analyze the log first.")
            else:
                show_statistics(stats)

        elif choice == "3":
            if stats is None:
                print("Please analyze the log first.")
            else:
                show_suspicious_ips(stats)

        elif choice == "4":
            if stats is None:
                print("Please analyze the log first.")
            else:
                save_report(stats)

        elif choice == "0":
            print("Goodbye!")
            break

        else:
            print("Invalid choice. Please try again.")


if __name__ == "__main__":
    main()
