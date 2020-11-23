using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace PVSS.net.Extensions
{
    public static class StringExtensions
    {
        public static bool IsHexString(this string str)
        {
            foreach (var c in str)
            {
                var isHex = ((c >= '0' && c <= '9') ||
                             (c >= 'a' && c <= 'f') ||
                             (c >= 'A' && c <= 'F'));

                if (!isHex)
                {
                    return false;
                }
            }

            return true;
        }

        //bonus, verify whether a string can be parsed as byte[]
        public static bool IsParseableToByteArray(this string str)
        {
            return IsHexString(str) && str.Length % 2 == 0;
        }

        public static string ToHexString(this string str)
        {
            return string
                .Concat(str.Select(x => ((int)x).ToString("x")));
        }

        public static byte[] ToByteArray(this string hex)
        {
            if (!hex.IsParseableToByteArray())
                throw new InvalidOperationException($"'{hex} is not suitable for conversion to a byte array");

            var numberChars = hex.Length;
            var bytes = new byte[numberChars / 2];
            for (var i = 0; i < numberChars; i += 2)
                bytes[i / 2] = Convert.ToByte(hex.Substring(i, 2), 16);
            return bytes;
        }

        public static byte[] ToHexEncodedByteArray(this string nonHexString)
        {
            return nonHexString.ToHexString().ToByteArray();
        }

        public static int GetHexVal(char hex)
        {
            int val = hex;
            //For uppercase A-F letters:
            //return val - (val < 58 ? 48 : 55);
            //For lowercase a-f letters:
            //return val - (val < 58 ? 48 : 87);
            //Or the two combined, but a bit slower:
            return val - (val < 58 ? 48 : val < 97 ? 55 : 87);
        }
    }
}
