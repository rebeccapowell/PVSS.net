using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace PVSS.net.Extensions
{
    public static class ByteExtensions
    {
        public static string ToHexString(this byte[] bytes)
        {
            var sb = new StringBuilder();
            foreach (var currentByte in bytes)
            {
                sb.Append(currentByte.ToString("x2"));
            }

            return sb.ToString();
        }

        public static byte[] ConcatZeroByte(this byte[] bytes)
        {
            return bytes.Concat(new byte[] { 0x00 }).ToArray();
        }

        public static byte[] Reverse(this byte[] bytes)
        {
            var reversed = new byte[bytes.Length];
            for (int i = 0; i < bytes.Length; i++)
            {
                reversed[(bytes.Length - i) - 1] = bytes[i];
            }

            return reversed;
        }

        public static byte[] ToByteArray(this string hex)
        {
            int NumberChars = hex.Length;
            byte[] bytes = new byte[NumberChars / 2];
            for (int i = 0; i < NumberChars; i += 2)
                bytes[i / 2] = Convert.ToByte(hex.Substring(i, 2), 16);
            return bytes;
        }

        public static int GetHexVal(char hex)
        {
            int val = (int)hex;
            //For uppercase A-F letters:
            //return val - (val < 58 ? 48 : 55);
            //For lowercase a-f letters:
            //return val - (val < 58 ? 48 : 87);
            //Or the two combined, but a bit slower:
            return val - (val < 58 ? 48 : (val < 97 ? 55 : 87));
        }
    }
}
