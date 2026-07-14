from analyzer import analyze_hash
from virustotal import check_virustotal

print("=== Hash Identifier ===")
print("1. Analyze Single Hash")
print("2. Analyze Hashes From File")


choice = input("\nChoose an option (1 or 2): ")

if choice == "1":
    hash_value = input("\nEnter hash: ")
    hash_type=analyze_hash(hash_value)

    if hash_type != "Invalid":
        stats, verdict = check_virustotal(hash_value)

        # report = open("report.txt", "w")


elif choice == "2":
    try:
        file = open("hashes.txt", "r")
        report = open("report.txt", "w")
        csv_report = open("report.csv", "w")
        csv_report.write("Hash,Type,Malicious,Harmless,Suspicious,Undetected,Verdict\n")

        total_hashes = 0
        valid_hashes = 0
        invalid_hashes = 0
        malicious_hashes = 0
        clean_hashes = 0
    
        for line in file:
            hash_value = line.strip()
            total_hashes += 1
            hash_type = analyze_hash(hash_value)

            if hash_type == "Invalid":
                invalid_hashes += 1
            else:
                valid_hashes += 1

            report.write("=" * 40 + "\n")
            report.write("Hash: " + hash_value + "\n")
            report.write("Type: " + hash_type + "\n")

            if hash_type != "Invalid":
                stats, verdict = check_virustotal(hash_value)

                if verdict == "MALICIOUS":
                    malicious_hashes += 1
                else:
                    clean_hashes += 1

                report.write("Malicious : " + str(stats["malicious"]) + "\n")
                report.write("Harmless  : " + str(stats["harmless"]) + "\n")
                report.write("Suspicious: " + str(stats["suspicious"]) + "\n")
                report.write("Undetected: " + str(stats["undetected"]) + "\n")
                report.write("Verdict   : " + verdict + "\n\n")

                csv_report.write(
                hash_value + "," +
                hash_type + "," +
                str(stats["malicious"]) + "," +
                str(stats["harmless"]) + "," +
                str(stats["suspicious"]) + "," +
                str(stats["undetected"]) + "," +
                verdict + "\n"
)

            else:
                report.write("Status    : Invalid hash\n\n")
                csv_report.write(
                hash_value + ",Invalid,-,-,-,-,Invalid\n"
)

            report.write("=" * 40 + "\n\n")

            print("\n" + "=" * 40)
            print("SUMMARY")
            print("=" * 40)
            print("Total Hashes      :", total_hashes)
            print("Valid Hashes      :", valid_hashes)
            print("Invalid Hashes    :", invalid_hashes)
            print("Malicious Hashes  :", malicious_hashes)
            print("Clean Hashes      :", clean_hashes)
        report.close()
        csv_report.close()
        file.close()
        

    except FileNotFoundError:
        print("Error: hashes.txt not found.")

else:
    print("Invalid choice. please select either 1 or 2.")