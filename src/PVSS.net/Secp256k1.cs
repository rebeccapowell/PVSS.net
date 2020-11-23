// // -----------------------------------------------------------------------
// // <copyright file="Secp256k1.cs" company="Rebecca Powell" year="2020">
// //      All rights are reserved. Reproduction or transmission in whole or
// //      in part, in any form or by any means, electronic, mechanical or
// //      otherwise, is prohibited without the prior written consent of the
// //      copyright owner.
// // </copyright>
// // <summary>
// //      Definition of the Secp256k1.cs class.
// // </summary>
// // -----------------------------------------------------------------------

using Org.BouncyCastle.Asn1.Sec;
using Org.BouncyCastle.Asn1.X9;

namespace PVSS.net
{
    /// <summary>
    ///     Class that implements ISecP2561
    ///     Stupid name. Is that an 'l' or a '1'. End shower thought.
    /// </summary>
    public class Secp256k1 : ISecp256k1
    {
        private static readonly X9ECParameters EC_PARAMETERS = SecNamedCurves.GetByName("secp256k1");
        private static readonly string ALGORITHM = "EC";
        private static readonly string PROVIDER = "SC";

        public string Algorithm => ALGORITHM;

        public string Provider => PROVIDER;

        public X9ECParameters Parameters => EC_PARAMETERS;
    }
}