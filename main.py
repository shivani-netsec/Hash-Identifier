print("=== Hash Identifier ===")

valid_chars = "0123456789abcdefABCDEF"

hash_value = input("Enter hash: ")
length = len(hash_value)

is_valid = True

for letter in hash_value:
    if letter not in valid_chars:
        is_valid = False

if not is_valid:
    print("Invalid hash")

else:
    length = len(hash_value)
    print("\n----- Analysis -----")
    print("Length:", length) 

    if length == 32:
        print("Valid MD5 Hash")

    elif length == 40:
        print("Valid SHA-1 Hash")

    elif length == 64:
        print("Valid SHA-256 Hash")
    elif length == 56:
        print("✅ Valid SHA-224 Hash")

    elif length == 96:
        print("✅ Valid SHA-384 Hash")

    elif length == 128:
        print("Valid SHA-512 Hash")

    else:
        print("Valid hexadecimal string, but unknown hash type.")