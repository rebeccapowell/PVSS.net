// // -----------------------------------------------------------------------
// // <copyright file="EcKeyPair.cs" company="Rebecca Powell" year="2020">
// //      All rights are reserved. Reproduction or transmission in whole or
// //      in part, in any form or by any means, electronic, mechanical or
// //      otherwise, is prohibited without the prior written consent of the
// //      copyright owner.
// // </copyright>
// // <summary>
// //      Definition of the EcKeyPair.cs class.
// // </summary>
// // -----------------------------------------------------------------------

using System;
using System.Linq;
using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;

namespace PVSS.net
{
    public static class EcKeyPair
    {
        /// <summary>
        ///     Generates an Asymmetric Key Pair.
        /// </summary>
        /// <returns></returns>
        public static AsymmetricCipherKeyPair GenerateKeyPair()
        {
            var curve = ECNamedCurveTable.GetByName("secp256k1");
            var domainParams = new ECDomainParameters(curve.Curve, curve.G, curve.N, curve.H, curve.GetSeed());

            var secureRandom = new SecureRandom();
            var keyParams = new ECKeyGenerationParameters(domainParams, secureRandom);

            var generator = new ECKeyPairGenerator("ECDSA");
            generator.Init(keyParams);
            var keyPair = generator.GenerateKeyPair();

            var privateKey = keyPair.Private as ECPrivateKeyParameters;
            var publicKey = keyPair.Public as ECPublicKeyParameters;

            Console.WriteLine($"Private key: {ToHex(privateKey.D.ToByteArrayUnsigned())}");
            Console.WriteLine($"Public key: {ToHex(publicKey.Q.GetEncoded())}");

            return keyPair;
        }

        private static string ToHex(byte[] data)
        {
            return string.Concat(data.Select(x => x.ToString("x2")));
        }
    }
}