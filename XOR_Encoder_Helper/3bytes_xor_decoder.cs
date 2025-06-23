public static byte[] XorDecode(byte[] encodedShellcode, byte[] key)
{
    if (key.Length != 3)
        throw new ArgumentException("Key must be 3 bytes long.");

    byte[] decoded = new byte[encodedShellcode.Length];

    for (int i = 0; i < encodedShellcode.Length; i++)
    {
        decoded[i] = (byte)(encodedShellcode[i] ^ key[i % 3]);
    }

    return decoded;
}