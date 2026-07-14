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