// // -----------------------------------------------------------------------
// // <copyright file="Participant.cs" company="Rebecca Powell" year="2020">
// //      All rights are reserved. Reproduction or transmission in whole or
// //      in part, in any form or by any means, electronic, mechanical or
// //      otherwise, is prohibited without the prior written consent of the
// //      copyright owner.
// // </copyright>
// // <summary>
// //      Definition of the Participant.cs class.
// // </summary>
// // -----------------------------------------------------------------------

using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;

namespace PVSS.net
{
    public class Participant
    {
        /// <summary>
        ///     Key Pair
        /// </summary>
        private readonly AsymmetricCipherKeyPair _keyPair;

        /// <summary>
        ///     Private key parameters
        /// </summary>
        private readonly ECPrivateKeyParameters _privateKeyParameters;

        /// <summary>
        ///     Public key parameters
        /// </summary>
        private readonly ECPublicKeyParameters _publicKeyParameters;

        /// <summary>
        ///     Creates a participant.
        /// </summary>
        /// <param name="name"></param>
        public Participant(string name)
        {
            Name = name;
            _keyPair = EcKeyPair.GenerateKeyPair();
            _privateKeyParameters = _keyPair.Private as ECPrivateKeyParameters;
            _publicKeyParameters = _keyPair.Public as ECPublicKeyParameters;
            PrivateKey = _privateKeyParameters.D.ToByteArray();
            PublicKey = _publicKeyParameters.Q.GetEncoded(true);
        }

        /// <summary>
        ///     The name (simply for debugging, a reference point.
        /// </summary>
        public string Name { get; set; }

        /// <summary>
        ///     The private key as a byte array
        /// </summary>
        public byte[] PrivateKey { get; set; }

        /// <summary>
        ///     The public key as a byte array
        /// </summary>
        public byte[] PublicKey { get; set; }
    }
}