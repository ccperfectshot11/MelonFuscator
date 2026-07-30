using System;
using System.Text;

namespace MelonFuscator.Runtime
{
    // This type is never called directly. Its method bodies are CLONED (copied at the
    // IL level) into the obfuscated module via AsmResolver's MemberCloner. For that
    // reason it only uses primitive BCL types (string, byte[], char) so it works both
    // on Unity Mono (net35/472) and on IL2CPP (CoreCLR net6+).
    public static class Decryptor
    {
        // Produces one keystream byte for position i from the key and the salt.
        // It does not depend on the plaintext, so Decrypt is symmetric with Encrypt.
        private static byte KeystreamByte(int i, byte[] key, byte[] salt)
        {
            // Mix position, key and salt through a rolling 64-bit FNV-style hash.
            ulong state = 1469598103934665603UL; // FNV offset basis
            state ^= (ulong)(uint)i;
            state *= 1099511628211UL;            // FNV prime
            state ^= key[i % key.Length];
            state *= 1099511628211UL;
            state ^= salt[i % salt.Length];
            state *= 1099511628211UL;
            state ^= (ulong)((i * 2654435761L) & 0xFFFFFFFFL);
            state *= 1099511628211UL;

            // Fold the 64 bits down into a single byte.
            byte b = (byte)(state ^ (state >> 8) ^ (state >> 16) ^ (state >> 24)
                          ^ (state >> 32) ^ (state >> 40) ^ (state >> 48) ^ (state >> 56));
            return (byte)(b ^ key[(i * 7 + 3) % key.Length] ^ salt[(i * 5 + 1) % salt.Length]);
        }

        // Transforms data <-> text (symmetric: the same code encrypts and decrypts).
        public static string Decrypt(byte[] data, byte[] salt, byte[] key)
        {
            byte[] output = new byte[data.Length];
            for (int i = 0; i < data.Length; i++)
                output[i] = (byte)(data[i] ^ KeystreamByte(i, key, salt));
            return Encoding.UTF8.GetString(output);
        }

        // Used by the Engine (outside the module) to encrypt at obfuscation time.
        public static byte[] Encrypt(string text, byte[] salt, byte[] key)
        {
            byte[] input = Encoding.UTF8.GetBytes(text);
            byte[] output = new byte[input.Length];
            for (int i = 0; i < input.Length; i++)
                output[i] = (byte)(input[i] ^ KeystreamByte(i, key, salt));
            return output;
        }
    }
}
