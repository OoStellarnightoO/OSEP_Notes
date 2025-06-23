import sys
import random
import string

# Generate a random 3-byte XOR key
def generate_key():
    return [random.randint(0, 255) for _ in range(3)]

# Convert input shellcode from string format to byte array
def parse_shellcode(shellcode_str):
    shellcode_str = shellcode_str.replace("\\x", "")
    return bytearray.fromhex(shellcode_str)

# XOR encode shellcode with a 3-byte key
def xor_encode(shellcode, key):
    encoded = bytearray()
    for i in range(len(shellcode)):
        encoded.append(shellcode[i] ^ key[i % 3])
    return encoded

# Format the encoded shellcode as a string for easy use in payloads
def format_encoded(encoded):
    return ''.join(f'\\x{byte:02x}' for byte in encoded)

def main():
    if len(sys.argv) != 2:
        print("Usage: python xor_encoder.py <shellcode>")
        print("Example: python xor_encoder.py \\\"\\xfc\\x48\\x83\\xe4\\xf0\\xe8\\x...\\\"")
        return

    shellcode_input = sys.argv[1]
    shellcode = parse_shellcode(shellcode_input)
    key = generate_key()

    print(f"[+] XOR Key: {[hex(b) for b in key]}")

    encoded_shellcode = xor_encode(shellcode, key)
    formatted = format_encoded(encoded_shellcode)

    print("[+] Encoded Shellcode:")
    print(formatted)

if __name__ == "__main__":
    main()