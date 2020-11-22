using System;
using System.Collections.Generic;
using System.Text;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;

namespace PVSS.net
{
    public class Participant
    {
        private readonly AsymmetricCipherKeyPair _keyPair;

        private readonly ECPrivateKeyParameters _privateKeyParameters;

        private readonly ECPublicKeyParameters _publicKeyParameters;

        public Participant(string name)
        {
            Name = name;
            _keyPair = EcKeyPair.GenerateKeyPair();
            _privateKeyParameters = _keyPair.Private as ECPrivateKeyParameters;
            _publicKeyParameters = _keyPair.Public as ECPublicKeyParameters;
            PrivateKey = _privateKeyParameters.D.ToByteArray();
            PublicKey = _publicKeyParameters.Q.GetEncoded(true);
        }

        public string Name { get; set; }

        public byte[] PrivateKey { get; set; }

        public byte[] PublicKey { get; set; }
    }
}
