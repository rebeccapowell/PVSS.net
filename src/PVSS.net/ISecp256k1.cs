using Org.BouncyCastle.Asn1.X9;

namespace PVSS.net
{
    public interface ISecp256k1
    {
        string Algorithm { get; }
        string Provider { get; }
        X9ECParameters Parameters { get; }
    }
}