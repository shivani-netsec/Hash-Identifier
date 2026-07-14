import requests

from dotenv import load_dotenv
import os
import requests

load_dotenv()

API_KEY = os.getenv("VT_API_KEY")


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
        verdict = "MALICIOUS"
        print("\nVerdict: MALICIOUS")
        print("Detected by", stats["malicious"], "security vendors.")
    else:
        verdict = "CLEAN"
        print("\nVerdict: CLEAN")
        print("No antivirus vendor detected this hash.")

    return stats, verdict