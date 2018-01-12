#if !(NETSTANDARD1_0)
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace MakingSense.SafeBrowsing
{
    public class CryptographyHelper
    {
        public static byte[] GenerateSHA256(byte[] input)
        {
            SHA256 sha256 = SHA256.Create();
            byte[] hash = sha256.ComputeHash(input);
            return hash;
        }

        public static byte[] GenerateSHA256(string inputString)
        {
            byte[] bytes = Encoding.UTF8.GetBytes(inputString);
            return GenerateSHA256(bytes);
        }

        public static byte[] GenerateSHA256(string inputString, int prefixSize)
        {
            var sha256 = GenerateSHA256(inputString);
            return sha256.Take(prefixSize).ToArray();
        }

        public static string GenerateSHA256String(string inputString)
        {
            return GetStringFromHash(GenerateSHA256(inputString));
        }

        public static string GenerateSHA256String(string inputString, int prefixSize)
        {
            return GetStringFromHash(GenerateSHA256(inputString, prefixSize));
        }

        private static string GetStringFromHash(byte[] hash)
        {
            StringBuilder result = new StringBuilder();
            for (int i = 0; i < hash.Length; i++)
            {
                result.Append(hash[i].ToString("X2"));
            }
            return result.ToString();
        }
    }
}
#endif