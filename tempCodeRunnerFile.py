print("=== Hash Identifier ===")
print("1. Analyze Single Hash")
print("2. Analyze Hashes From File")

valid_chars = "0123456789abcdefABCDEF"

choice = input("\nChoose an option (1 or 2): ")

if choice == "1":
    hash_value = input("\nEnter hash: ")

    length = len(hash_value)

    is_valid = True

for letter in hash_value:
    if letter not in valid_chars:
        is_valid = False

if not is_valid:
    print("Invalid hash")

else:
    length = len(hash_value)
    print("\n" + "=" * 40)
    print("         HASH ANALYSIS REPORT")
    print("=" * 40)
    print("Hash        :", hash_value)
    print("Length : ", length) 
    print("Hexadecimal : Yes")

    if length == 32:
        print("Hash Type : MD5")
        print("Security : Weak(Collision attack possible)")

    elif length == 40:
        print("Hash Type : SHA-1")
        print("Security : Weak(Deprecated)")

    elif length == 64:
        print("Hash Type :SHA-256")
        print("Security : Medium(Still secure for most purposes)")

    elif length == 56:
        print("Hash Type : SHA-224")
        print("Security : Medium(Still secure for most purposes)")

    elif length == 96:
        print("Hash Type : SHA-384")
        print("Security : High(Currently secure)")

    elif length == 128:
        print("Hash Type :SHA-512")
        print("Security : High(Currently secure)")
    
    elif choice == "2":
        print("Reading hashes from file...")

    else:
        print("Valid hexadecimal string, but unknown hash type.")