import requests
from config import API_KEY

valid_chars = "0123456789abcdefABCDEF" 

hash_info = {
    32: ("MD5", "Weak (Collision attack possible)"),
    40: ("SHA-1", "Weak (Deprecated)"),
    56: ("SHA-224", "Medium (Still secure for most purposes)"),
    64: ("SHA-256", "Medium (Still secure for most purposes)"),
    96: ("SHA-384", "High (Currently secure)"),
    128: ("SHA-512", "High (Currently secure)")
}

def check_virustotal(hash_value):
    url = "https://www.virustotal.com/api/v3/files/" + hash_value
    headers = {
        "x-apikey": API_KEY
    }

    response = requests.get(url, headers=headers)
   
    if response.status_code != 200:
        print("\nVirusTotal Analysis")
        print("-" * 25)
        print("Could not analyze this hash.")
        return
    

    data = response.json()
    stats = data["data"]["attributes"]["last_analysis_stats"]
    print("\nVirusTotal Analysis")
    print("-" * 25)
    print("Malicious :", stats["malicious"])
    print("Harmless  :", stats["harmless"])
    print("Suspicious:", stats["suspicious"])
    print("Undetected:", stats["undetected"])

    if stats["malicious"] > 0:
       print("\nVerdict: MALICIOUS")
       print("Detected by", stats["malicious"], "security vendors.")

    else:
       print("\nVerdict: CLEAN")
       print("No antivirus vendor detected this hash.")


def analyze_hash(hash_value):
    length = len(hash_value)

    is_valid = True

    for letter in hash_value:
        if letter not in valid_chars:
            is_valid = False

    if not is_valid:
        print("\n" + "=" * 40)
        print("HASH ANALYSIS REPORT")
        print("=" * 40)
        print("Hash        :", hash_value)
        print("Status      : Invalid hexadecimal hash")
        return "Invalid"

    print("\n" + "=" * 40)
    print("         HASH ANALYSIS REPORT")
    print("=" * 40)
    print("Hash        :", hash_value)
    print("Length      : ", length) 
    print("Hexadecimal : Yes")

    if length in hash_info:
        hash_type, security = hash_info[length]

        print("Hash Type  :", hash_type)
        print("Security   :", security)

        return hash_type

    else:
        print("Hash Type  : Unknown")
        return "Unknown"

print("=== Hash Identifier ===")
print("1. Analyze Single Hash")
print("2. Analyze Hashes From File")


choice = input("\nChoose an option (1 or 2): ")

if choice == "1":
    hash_value = input("\nEnter hash: ")
    hash_type=analyze_hash(hash_value)

    if hash_type != "Invalid":
        check_virustotal(hash_value)
   

elif choice == "2":
    try:
        file = open("hashes.txt", "r")
        report = open("report.txt", "w")
    
        for line in file:
            hash_value = line.strip()
            hash_type = analyze_hash(hash_value)

            if hash_type != "Invalid":
                check_virustotal(hash_value)

        report.close()
        file.close()

    except FileNotFoundError:
        print("Error: hashes.txt not found.")

else:
    print("Invalid choice. please select either 1 or 2.")