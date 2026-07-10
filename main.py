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
        print("Security:Weak(Collision attack possible)")

    elif length == 40:
        print("Valid SHA-1 Hash")
        print("Security:Weak(Deprecated)")

    elif length == 64:
        print("Valid SHA-256 Hash")
        print("Security:Medium(Still secure for most purposes)")

    elif length == 56:
        print("✅ Valid SHA-224 Hash")
        print("Security:Medium(Still secure for most purposes)")

    elif length == 96:
        print("✅ Valid SHA-384 Hash")
        print("Security:High(Currently secure)")

    elif length == 128:
        print("✅ Valid SHA-512 Hash")
        print("Security:High(Currently secure)")

    else:
        print("Valid hexadecimal string, but unknown hash type.")