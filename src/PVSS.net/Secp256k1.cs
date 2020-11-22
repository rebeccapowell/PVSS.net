using System;
using System.Collections.Generic;
using System.Text;
using Org.BouncyCastle.Asn1.Sec;
using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Math.EC;

namespace PVSS.net
{
    public interface ISecp256k1
    {
        string Algorithm { get; }
        string Provider { get; }
        X9ECParameters Parameters { get; }
    }

    public class Secp256k1 : ISecp256k1
    {
        private static X9ECParameters EC_PARAMETERS = SecNamedCurves.GetByName("secp256k1");
        private static string ALGORITHM = "EC";
        private static string PROVIDER = "SC";

        public string Algorithm => ALGORITHM;
        
        public string Provider => PROVIDER;
        
        public X9ECParameters Parameters => EC_PARAMETERS;
    }
}
