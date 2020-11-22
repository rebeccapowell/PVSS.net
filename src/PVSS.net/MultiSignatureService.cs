using System;
using System.Collections.Generic;
using System.Linq;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Math.EC;
using Org.BouncyCastle.Security;

namespace PVSS.net
{
    public class MultiSignatureService : IMultiSignatureService
    {
		private static SecureRandom _secureRandom;
        private readonly ISecp256k1 _secp256k1;

		public MultiSignatureService(ISecp256k1 secp256k1)
		{
            _secp256k1 = secp256k1;
			_secureRandom = new SecureRandom();
			var seed = _secureRandom.GenerateSeed(32);
			_secureRandom.SetSeed(seed);
            
        }

		public byte[] ComputeCommitmentSecret()
		{
			var r = new byte[32];
			_secureRandom.NextBytes(r);
			BigInteger commitmentSecret = new BigInteger(r);
			while (commitmentSecret.CompareTo(BigInteger.One) < 0 && commitmentSecret.CompareTo(_secp256k1.Parameters.N) >= 0)
			{
				r = Sha3(r);
				commitmentSecret = new BigInteger(r);
			}
			return r;
		}

		public byte[] ComputeCommitment(byte[] commitmentSecret)
		{
            var secretInt = new BigInteger(commitmentSecret);
			var basePointG = _secp256k1.Parameters.G;
			var commitmentPointR = basePointG.Multiply(secretInt);
			return commitmentPointR.GetEncoded(true);
		}

		public virtual byte[] ComputeCommitmentHash(byte[] commitment)
		{
			return Sha256(commitment);
		}

		public bool ValidateCommitment(byte[] commitment, byte[] commitmentHash)
        {
            var computedHash = Sha256(commitment);
            return computedHash.SequenceEqual(commitmentHash);
        }

		public virtual byte[] AggregateCommitments(List<byte[]> commitments, long bitmapCommitments)
		{
			var idx = 0;
			ECPoint aggregatedCommitment = null;
            var result = new byte[0];

			foreach (var commitment in commitments)
			{
				if (0 != ((1 << idx) & bitmapCommitments))
                {
                    var decodedCommitment = _secp256k1.Parameters.Curve.DecodePoint((byte[])commitment.Clone());
                    aggregatedCommitment = null == aggregatedCommitment ? decodedCommitment : aggregatedCommitment.Add(decodedCommitment);
                }
				idx++;
			}
			if (null != aggregatedCommitment)
			{
				result = aggregatedCommitment.GetEncoded(true);
			}
			return result;
		}

		private byte[] ConcatenatePublicKeys(List<byte[]> publicKeys, long bitmapCommitments)
		{
			var idx = 0;
			var result = new byte[0];
			foreach (var key in publicKeys)
			{
				if (0 != ((1 << idx) & bitmapCommitments))
				{
                    var z = new byte[result.Length + key.Length];
					// concatenate the public keys
					result = Concat(result, key);
				}
				idx++;
			}
			return result;
		}

		public static byte[] Concat(byte[] first, byte[] second)
        {
            var ret = new byte[first.Length + second.Length];
            Buffer.BlockCopy(first, 0, ret, 0, first.Length);
            Buffer.BlockCopy(second, 0, ret, first.Length, second.Length);
            return ret;
        }

		public byte[] ComputeChallenge(List<byte[]> signers, byte[] publicKey, byte[] aggregatedCommitment, byte[] message, long bitmapCommitments)
		{
			var challenge = new byte[0];
            if (0 == bitmapCommitments)
			{
				return challenge;
			}
			challenge = ConcatenatePublicKeys(signers, bitmapCommitments);
			challenge = Concat(challenge, publicKey);
			challenge = Concat(challenge, aggregatedCommitment);
			challenge = Concat(challenge, message);

			var challengeInt = new BigInteger(1, Sha3(challenge));

			challengeInt = challengeInt.Mod(_secp256k1.Parameters.N);
			return challengeInt.ToByteArray();
		}

		public virtual byte[] ComputeSignatureShare(byte[] challenge, byte[] privateKey, byte[] commitmentSecret)
		{
			var curveOrder = _secp256k1.Parameters.N;
            var challengeInt = new BigInteger(challenge);
			var privateKeyInt = new BigInteger(privateKey);
			var commitmentSecretInt = new BigInteger(commitmentSecret);
			var sigShare = commitmentSecretInt.Add(challengeInt.Multiply(privateKeyInt).Mod(curveOrder)).Mod(curveOrder);
			return sigShare.ToByteArray();
		}

		public bool VerifySignatureShare(List<byte[]> publicKeys, byte[] publicKey, byte[] signature, byte[] aggCommitment, byte[] commitment, byte[] message, long bitmap)
		{
			var basePointG = _secp256k1.Parameters.G;
            var publicKeyPoint = _secp256k1.Parameters.Curve.DecodePoint((byte[])publicKey.Clone());
			var commitmentRInt = new BigInteger(commitment);
			var challenge = ComputeChallenge(publicKeys, publicKey, aggCommitment, message, bitmap);
			var challengeInt = (new BigInteger(1, challenge));
			var commitmentR2 = basePointG.Multiply(new BigInteger(signature)).Subtract(publicKeyPoint.Multiply(challengeInt));
			return new BigInteger(commitmentR2.GetEncoded(true)).Equals(commitmentRInt);
		}

		public byte[] AggregateSignatures(List<byte[]> signatureShares, long bitmapSigners)
		{
			byte idx = 0;
			var curveOrder = _secp256k1.Parameters.N;
			var aggregatedSignature = BigInteger.Zero;

			foreach (var signature in signatureShares)
			{
				if (0 != ((1 << idx) & bitmapSigners))
				{
					aggregatedSignature = aggregatedSignature.Add(new BigInteger(signature)).Mod(curveOrder);
				}
				idx++;
			}

			return aggregatedSignature.ToByteArray();
		}

		public bool VerifyAggregatedSignature(List<byte[]> signers, byte[] aggregatedSignature, byte[] aggregatedCommitment, byte[] message, long bitmapSigners)
		{
            var idx = 0;
			ECPoint sum = null;

            var aggregatedCommitmentPoint = _secp256k1.Parameters.Curve.DecodePoint((byte[])aggregatedCommitment.Clone());
			foreach (byte[] publicKey in signers)
			{
				if (0 != ((1 << idx) & bitmapSigners))
				{
					var publicKeyPoint = _secp256k1.Parameters.Curve.DecodePoint((byte[])publicKey.Clone());

					//compute challenge H1(<L'>||Xi||R||m)
					var tempChallenge = new BigInteger(ComputeChallenge(signers, publicKey, aggregatedCommitment, message, bitmapSigners));
					var tmp = publicKeyPoint.Multiply(tempChallenge);
					// do the sum
					sum = null == sum ? tmp : sum.Add(tmp);
				}
				idx++;
			}

			var sG = _secp256k1.Parameters.G.Multiply(new BigInteger(aggregatedSignature));

			sum = sG.Subtract(sum);

			return aggregatedCommitmentPoint.Equals(sum);
		}

        private byte[] Sha3(byte[] data)
        {
            var digest = new Sha3Digest(512);
            digest.BlockUpdate(data, 0, data.Length);
            var result = new byte[64]; // 512 / 8 = 64
            digest.DoFinal(result, 0);
            return result;
        }

        private byte[] Sha256(byte[] data)
        {
			Sha256Digest digest = new Sha256Digest();
            digest.BlockUpdate(data, 0, data.Length);
            var result = new byte[digest.GetDigestSize()];
            digest.DoFinal(result, 0);

            return result;
		}
	}
}
