using System;
using System.Collections.Generic;
using System.Text;
using GuardNet;
using Org.BouncyCastle.Crypto.Digests;

namespace PVSS.net
{
    public static class Digests
    {
        /// <summary>
        ///     SAH3 hash of [data].
        /// </summary>
        /// <param name="data"></param>
        /// <returns></returns>
        public static byte[] Sha3(byte[] data)
        {
            Guard.NotNull(data, nameof(data));
            Guard.NotLessThanOrEqualTo(data.Length, 0, nameof(data));

            var digest = new Sha3Digest(512);
            digest.BlockUpdate(data, 0, data.Length);
            var result = new byte[64]; // 512 / 8 = 64
            digest.DoFinal(result, 0);
            return result;
        }

        /// <summary>
        ///     SHA256 hash of [data].
        /// </summary>
        /// <param name="data"></param>
        /// <returns></returns>
        public static byte[] Sha256(byte[] data)
        {
            Guard.NotNull(data, nameof(data));
            Guard.NotLessThanOrEqualTo(data.Length, 0, nameof(data));

            var digest = new Sha256Digest();
            digest.BlockUpdate(data, 0, data.Length);
            var result = new byte[digest.GetDigestSize()];
            digest.DoFinal(result, 0);

            return result;
        }
    }
}
