// // -----------------------------------------------------------------------
// // <copyright file="ByteExtensions.cs" company="Rebecca Powell" year="2020">
// //      All rights are reserved. Reproduction or transmission in whole or
// //      in part, in any form or by any means, electronic, mechanical or
// //      otherwise, is prohibited without the prior written consent of the
// //      copyright owner.
// // </copyright>
// // <summary>
// //      Definition of the ByteExtensions.cs class.
// // </summary>
// // -----------------------------------------------------------------------

using System;
using System.Linq;
using System.Text;

namespace PVSS.net.Extensions
{
    public static class ByteExtensions
    {
        public static string ToHexString(this byte[] bytes)
        {
            var sb = new StringBuilder();
            foreach (var currentByte in bytes) sb.Append(currentByte.ToString("x2"));

            return sb.ToString();
        }

        public static byte[] ConcatZeroByte(this byte[] bytes)
        {
            return bytes.Concat(new byte[] {0x00}).ToArray();
        }

        public static byte[] Reverse(this byte[] bytes)
        {
            var reversed = new byte[bytes.Length];
            for (var i = 0; i < bytes.Length; i++) reversed[bytes.Length - i - 1] = bytes[i];

            return reversed;
        }
    }
}