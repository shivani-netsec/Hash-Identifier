valid_chars = "0123456789abcdefABCDEF" 

def analyze_hash(hash_value):
    length = len(hash_value)

    is_valid = True

    for letter in hash_value:
        if letter not in valid_chars:
            is_valid = False

    if not is_valid:
        print("Invalid hash")
        return
        
    print("\n" + "=" * 40)
    print("         HASH ANALYSIS REPORT")
    print("=" * 40)
    print("Hash        :", hash_value)
    print("Length      : ", length) 
    print("Hexadecimal : Yes")

    if length == 32:
        print("Hash Type  : MD5")
        print("Security   : Weak(Collision attack possible)")
        return "MD5"

    elif length == 40:
        print("Hash Type  : SHA-1")
        print("Security : Weak(Deprecated)")
        return "SHA-1"

    elif length == 64:
        print("Hash Type  : SHA-256")
        print("Security   : Medium(Still secure for most purposes)")
        return "SHA-256"

    elif length == 56:
        print("Hash Type  : SHA-224")
        print("Security   : Medium(Still secure for most purposes)")
        return "SHA-224"

    elif length == 96:
        print("Hash Type  : SHA-384")
        print("Security   : High(Currently secure)")
        return "SHA-384"

    elif length == 128:
        print("Hash Type  : SHA-512")
        print("Security   : High(Currently secure)")
        return "SHA-512"

    else:
        print("Valid hexadecimal string, but unknown hash type.")
        return "Unknown"

print("=== Hash Identifier ===")
print("1. Analyze Single Hash")
print("2. Analyze Hashes From File")


choice = input("\nChoose an option (1 or 2): ")

if choice == "1":
    hash_value = input("\nEnter hash: ")
    hash_type=analyze_hash(hash_value)
   

elif choice == "2":
    file=open("hashes.txt","r")
    report = open("report.txt", "w")

    for line in file:
        report.write(line)
        analyze_hash(line.strip())

    report.close()
    file.close()

else:
    print("Invalid choice. please select either 1 or 2.")