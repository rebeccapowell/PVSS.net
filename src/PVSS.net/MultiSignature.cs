// // -----------------------------------------------------------------------
// // <copyright file="MultiSignature.cs" company="Rebecca Powell" year="2020">
// //      All rights are reserved. Reproduction or transmission in whole or
// //      in part, in any form or by any means, electronic, mechanical or
// //      otherwise, is prohibited without the prior written consent of the
// //      copyright owner.
// // </copyright>
// // <summary>
// //      Definition of the MultiSignature.cs class.
// // </summary>
// // -----------------------------------------------------------------------

using System;
using System.Collections.Generic;
using System.Linq;
using GuardNet;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Math.EC;
using Org.BouncyCastle.Security;

namespace PVSS.net
{
    public class MultiSignature : IMultiSignature
    {
        private static SecureRandom _secureRandom;
        private readonly ISecp256k1 _secp256k1;

        /// <summary>
        ///     Class implementing Belare and Neven Multi-signature
        ///     See "Multi-Signatures in the Plain Public-Key Model and a General Forking Lemma"
        ///     - <see href="https://cseweb.ucsd.edu/~mihir/papers/multisignatures-ccs.pdf" />
        ///     - Port <see href="https://github.com/ElrondNetwork/elrond-node-prototype/blob/master/elrond-core/" />
        /// </summary>
        /// <param name="secp256k1"></param>
        public MultiSignature(ISecp256k1 secp256k1)
        {
            _secp256k1 = secp256k1;
            _secureRandom = new SecureRandom();
            var seed = _secureRandom.GenerateSeed(32);
            _secureRandom.SetSeed(seed);
        }

        /// <summary>
        ///     Compute the commitment secret
        ///     Choose a random r (commitment secret) in interval[1, n-1], where n is the order of the curve
        /// </summary>
        /// <returns>Commitment secret as a byte array.</returns>
        public byte[] ComputeCommitmentSecret()
        {
            var r = new byte[32];
            _secureRandom.NextBytes(r);
            var commitmentSecret = new BigInteger(r);

            // Ensure r is not 0, r below order of curve...
            while (commitmentSecret.CompareTo(BigInteger.One) < 0 ||
                   commitmentSecret.CompareTo(_secp256k1.Parameters.N) >= 0)
            {
                //r = Sha3(r);
                _secureRandom.NextBytes(r);
                commitmentSecret = new BigInteger(r);
            }

            return r;
        }

        /// <summary>
        ///     Compute the commitment Point
        /// </summary>
        /// <param name="commitmentSecret">CommitmentSecret the commitment secret as a byte array</param>
        /// <returns>Commitment as a byte array</returns>
        public byte[] ComputeCommitment(byte[] commitmentSecret)
        {
            // Not to self. Wish these were chainable guards
            // i.e. commitmentSecret.Guard.NotNull().NotEmpty(new CustomException("Cannot be empty"))
            Guard.NotNull(commitmentSecret, nameof(commitmentSecret));
            Guard.NotLessThanOrEqualTo(commitmentSecret.Length, 0, nameof(commitmentSecret));

            // compute commitment R = r*G
            var secretInt = new BigInteger(commitmentSecret);
            var basePointG = _secp256k1.Parameters.G;
            var commitmentPointR = basePointG.Multiply(secretInt);
            return commitmentPointR.GetEncoded(true);
        }

        /// <summary>
        ///     Computes the commitment Hash
        /// </summary>
        /// <param name="commitment">Commitment the commitment as a byte array.</param>
        /// <returns>Commitment hash as a byte array</returns>
        public virtual byte[] ComputeCommitmentHash(byte[] commitment)
        {
            Guard.NotNull(commitment, nameof(commitment));
            Guard.NotLessThanOrEqualTo(commitment.Length, 0, nameof(commitment));

            return Sha256(commitment);
        }

        /// <summary>
        ///     Verifies the commitmentHash is resulted from commitment
        /// </summary>
        /// <param name="commitment">Commitment as a byte array</param>
        /// <param name="commitmentHash">CommitmentHash the commitment hash as a byte array</param>
        /// <returns>true if commitmentHash is the Hash of commitment, false otherwise</returns>
        public bool ValidateCommitment(byte[] commitment, byte[] commitmentHash)
        {
            Guard.NotNull(commitment, nameof(commitment));
            Guard.NotLessThanOrEqualTo(commitment.Length, 0, nameof(commitment));

            Guard.NotNull(commitmentHash, nameof(commitmentHash));
            Guard.NotLessThanOrEqualTo(commitmentHash.Length, 0, nameof(commitmentHash));

            var computedHash = Sha256(commitment);
            return computedHash.SequenceEqual(commitmentHash);
        }

        /// <summary>
        ///     Calculate the aggregated commitment
        /// </summary>
        /// <param name="commitments">An array listToTable of commitments from each signer</param>
        /// <param name="bitmapCommitments">Commitments the bitmap of considered commitments from the whole listToTable</param>
        /// <returns>the aggregated commitment</returns>
        public virtual byte[] AggregateCommitments(List<byte[]> commitments, long bitmapCommitments)
        {
            Guard.NotNull(commitments, nameof(commitments));
            Guard.NotLessThanOrEqualTo(commitments.Count, 0, nameof(commitments));

            var idx = 0;
            ECPoint aggregatedCommitment = null;
            var result = new byte[0];

            foreach (var commitment in commitments)
            {
                if (0 != ((1 << idx) & bitmapCommitments))
                {
                    // aggregate the commits
                    var decodedCommitment = _secp256k1.Parameters.Curve.DecodePoint((byte[]) commitment.Clone());
                    aggregatedCommitment = null == aggregatedCommitment
                        ? decodedCommitment
                        : aggregatedCommitment.Add(decodedCommitment);
                }

                idx++;
            }

            if (null != aggregatedCommitment) result = aggregatedCommitment.GetEncoded(true);
            return result;
        }

        /// <summary>
        ///     Computes the challenge according to Belare Naveen multi-signature algorithm:
        ///     - H1(
        ///     <L'>||Xi||R||m), where H1 is a Hashing function, e.g Sha3, Xi is the public key,
        ///  - R is the aggregated commitment, and m is the message.
        /// 
        /// 
        /// </summary>
        /// <param name="signers">the listToTable of signee's (consensus group's) public keys</param>
        /// <param name="publicKey">own public key</param>
        /// <param name="aggregatedCommitment">the aggregated commitment from all signers as a byte array</param>
        /// <param name="message">the message to be signed</param>
        /// <param name="bitmapCommitments">
        ///     commitment mask (byte), bit is 1 if corresponding signer participates in signing or 0
        ///     otherwise
        /// </param>
        /// <returns>the challenge as a byte array</returns>
        public byte[] ComputeChallenge(List<byte[]> signers, byte[] publicKey, byte[] aggregatedCommitment,
            byte[] message, long bitmapCommitments)
        {
            Guard.NotNull(signers, nameof(signers));
            Guard.NotLessThanOrEqualTo(signers.Count, 0, nameof(signers));
            Guard.NotNull(publicKey, nameof(publicKey));
            Guard.NotLessThanOrEqualTo(publicKey.Length, 0, nameof(publicKey));
            Guard.NotNull(aggregatedCommitment, nameof(aggregatedCommitment));
            Guard.NotLessThanOrEqualTo(aggregatedCommitment.Length, 0, nameof(aggregatedCommitment));
            Guard.NotNull(message, nameof(message));
            Guard.NotLessThanOrEqualTo(message.Length, 0, nameof(message));

            var challenge = new byte[0];
            if (0 == bitmapCommitments) return challenge;

            // compute <L'> as concatenation of participating signers public keys
            challenge = ConcatenatePublicKeys(signers, bitmapCommitments);

            // do rest of concatenation <L'> || public key
            challenge = Concat(challenge, publicKey);

            // do <L'> || public key || R
            challenge = Concat(challenge, aggregatedCommitment);

            // do <L'> || public key || R || m
            challenge = Concat(challenge, message);

            // do computing hash as BigInteger
            var challengeInt = new BigInteger(1, Sha3(challenge));

            // reduce the challenge modulo curve order
            return challengeInt.Mod(_secp256k1.Parameters.N).ToByteArray();
        }

        /// <summary>
        ///     Computes the signature share associated to this private key according to formula:
        ///     - s = ri + challenge* xi, where ri is the private part of the commitment, xi is own
        ///     - private key, and challenge is the result of computeChallenge
        /// </summary>
        /// <param name="challenge">the calculated challenge associated with own public key</param>
        /// <param name="privateKey">the own private key</param>
        /// <param name="commitmentSecret">the commitment secret</param>
        /// <returns>the signature share</returns>
        public virtual byte[] ComputeSignatureShare(byte[] challenge, byte[] privateKey, byte[] commitmentSecret)
        {
            Guard.NotNull(challenge, nameof(challenge));
            Guard.NotLessThanOrEqualTo(challenge.Length, 0, nameof(challenge));
            Guard.NotNull(privateKey, nameof(privateKey));
            Guard.NotLessThanOrEqualTo(privateKey.Length, 0, nameof(privateKey));
            Guard.NotNull(commitmentSecret, nameof(commitmentSecret));
            Guard.NotLessThanOrEqualTo(commitmentSecret.Length, 0, nameof(commitmentSecret));

            var curveOrder = _secp256k1.Parameters.N;
            var challengeInt = new BigInteger(challenge);
            var privateKeyInt = new BigInteger(privateKey);
            var commitmentSecretInt = new BigInteger(commitmentSecret);
            var sigShare = commitmentSecretInt.Add(challengeInt.Multiply(privateKeyInt).Mod(curveOrder))
                .Mod(curveOrder);
            return sigShare.ToByteArray();
        }

        /// <summary>
        ///     Verifies the signature share (R, s) on a message m, according to Schnorr verification algorithm:
        ///     1. check if s is in [1, order-1]
        ///     2. Compute c = H(
        ///     < L'> || R || publicKey || message)
        /// 3.Compute R2 = s * G - c * publicKey
        /// 4. if R2 = O, return false
        /// return R2 == R
        /// 
        /// 
        /// </summary>
        /// <param name="publicKeys">array list of signee's public keys</param>
        /// <param name="publicKey">public key for the signature share</param>
        /// <param name="signature">signature share to verify</param>
        /// <param name="aggCommitment">aggregated commitment</param>
        /// <param name="commitment">commitment for signature share</param>
        /// <param name="message">message for which the signature was computed</param>
        /// <param name="bitmap">bitmap of participating signers out of all signers list</param>
        /// <returns>true if signature is verified, false otherwise</returns>
        public bool VerifySignatureShare(List<byte[]> publicKeys, byte[] publicKey, byte[] signature,
            byte[] aggCommitment, byte[] commitment, byte[] message, long bitmap)
        {
            Guard.NotNull(publicKeys, nameof(publicKeys));
            Guard.NotLessThanOrEqualTo(publicKeys.Count, 0, nameof(publicKeys));
            Guard.NotNull(publicKey, nameof(publicKey));
            Guard.NotLessThanOrEqualTo(publicKey.Length, 0, nameof(publicKey));
            Guard.NotNull(signature, nameof(signature));
            Guard.NotLessThanOrEqualTo(signature.Length, 0, nameof(signature));
            Guard.NotNull(aggCommitment, nameof(aggCommitment));
            Guard.NotLessThanOrEqualTo(aggCommitment.Length, 0, nameof(aggCommitment));
            Guard.NotNull(message, nameof(message));
            Guard.NotLessThanOrEqualTo(message.Length, 0, nameof(message));

            // Compute R2 = s*G + c*publicKey
            var basePointG = _secp256k1.Parameters.G;
            var publicKeyPoint = _secp256k1.Parameters.Curve.DecodePoint((byte[]) publicKey.Clone());

            // do computing commitmentRInt
            var commitmentRInt = new BigInteger(commitment);

            // do calculating challenge
            var challenge = ComputeChallenge(publicKeys, publicKey, aggCommitment, message, bitmap);

            // BigInteger challenge
            var challengeInt = new BigInteger(1, challenge);

            // Compute R2 = s*G - c*publicKey
            var commitmentR2 = basePointG.Multiply(new BigInteger(signature))
                .Subtract(publicKeyPoint.Multiply(challengeInt));

            return new BigInteger(commitmentR2.GetEncoded(true)).Equals(commitmentRInt);
        }

        /// <summary>
        ///     Aggregates the signature shares according to the participating signers
        /// </summary>
        /// <param name="signatureShares">signatureShares the listToTable of signature shares</param>
        /// <param name="bitmapSigners">the participating signers as a bitmap (byte)</param>
        /// <returns>the aggregated signature</returns>
        public byte[] AggregateSignatures(List<byte[]> signatureShares, long bitmapSigners)
        {
            Guard.NotNull(signatureShares, nameof(signatureShares));
            Guard.NotLessThanOrEqualTo(signatureShares.Count, 0, nameof(signatureShares));

            byte idx = 0;
            var curveOrder = _secp256k1.Parameters.N;
            var aggregatedSignature = BigInteger.Zero;

            foreach (var signature in signatureShares)
            {
                if (0 != ((1 << idx) & bitmapSigners))
                    aggregatedSignature = aggregatedSignature.Add(new BigInteger(signature)).Mod(curveOrder);
                idx++;
            }

            return aggregatedSignature.ToByteArray();
        }

        /// <summary>
        ///     Verifies a multi-signature as below:
        ///     s*G == R + sum(H1(
        ///     <L'> || Xi || R || m)*Xi*Bitmap[i]), where:
        ///  -   s is the aggregated signature
        ///  -   G is the base point on the chosen curve
        ///  -   H1 is the Hash function, different than one used for the commitment hash
        ///  -   
        ///     
        ///     <L'> is the set of all signers' s public keys( the consensus group used in SPoS)
        ///         - Xi is the public key for signer i
        ///         - R is the aggregated commitment
        ///         - m is the message that was signed with s
        ///         - Bitmap[ i] the i bit inside a bitmap, set to 1 if signer i in
        ///     <L'> has signed or 0 otherwise
        /// 
        /// 
        /// </summary>
        /// <param name="signers">an ArrayList containing all possible signee's public keys</param>
        /// <param name="aggregatedSignature">the aggregated signature to be verified</param>
        /// <param name="aggregatedCommitment">the aggregated commitment</param>
        /// <param name="message">the message on which the signature was calculated</param>
        /// <param name="bitmapSigners">the bitmap of signers</param>
        /// <returns>true if aggregated signature is valid, false otherwise</returns>
        public bool VerifyAggregatedSignature(List<byte[]> signers, byte[] aggregatedSignature,
            byte[] aggregatedCommitment, byte[] message, long bitmapSigners)
        {
            Guard.NotNull(signers, nameof(signers));
            Guard.NotLessThanOrEqualTo(signers.Count, 0, nameof(signers));
            Guard.NotNull(aggregatedSignature, nameof(aggregatedSignature));
            Guard.NotLessThanOrEqualTo(aggregatedSignature.Length, 0, nameof(aggregatedSignature));
            Guard.NotNull(aggregatedSignature, nameof(aggregatedSignature));
            Guard.NotLessThanOrEqualTo(aggregatedSignature.Length, 0, nameof(aggregatedSignature));
            Guard.NotNull(message, nameof(message));
            Guard.NotLessThanOrEqualTo(message.Length, 0, nameof(message));

            var idx = 0;
            ECPoint sum = null;

            var aggregatedCommitmentPoint =
                _secp256k1.Parameters.Curve.DecodePoint((byte[]) aggregatedCommitment.Clone());

            // computing sum(H1(<L'> || Xi || R || m)*Xi*Bitmap[i])
            foreach (var publicKey in signers)
            {
                if (0 != ((1 << idx) & bitmapSigners))
                {
                    var publicKeyPoint = _secp256k1.Parameters.Curve.DecodePoint((byte[]) publicKey.Clone());

                    // compute challenge H1(<L'>||Xi||R||m)
                    var tempChallenge = new BigInteger(ComputeChallenge(signers, publicKey, aggregatedCommitment,
                        message, bitmapSigners));
                    var tmp = publicKeyPoint.Multiply(tempChallenge);
                    // do the sum (H1 * Xi * Bitmap[i])
                    sum = null == sum ? tmp : sum.Add(tmp);
                }

                idx++;
            }

            // do computing s*G
            var sG = _secp256k1.Parameters.G.Multiply(new BigInteger(aggregatedSignature));

            // do calculating sG-sum(H1(...)Xi)
            sum = sG.Subtract(sum);

            // comparison R == sG - sum(H1(<L'>||Xi||R||m)Xi)
            return aggregatedCommitmentPoint.Equals(sum);
        }

        /// <summary>
        ///     Concatenates the specified pubic keys.
        /// </summary>
        /// <param name="publicKeys">the list of signee's (consensus group's) public keys</param>
        /// <param name="bitmapCommitments">bitmap showing which elements from publicKeys to concatenate</param>
        /// <returns>a byte array holding the concatenation of public keys</returns>
        private byte[] ConcatenatePublicKeys(List<byte[]> publicKeys, long bitmapCommitments)
        {
            Guard.NotNull(publicKeys, nameof(publicKeys));
            Guard.NotLessThanOrEqualTo(publicKeys.Count, 0, nameof(publicKeys));

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

        /// <summary>
        ///     Concatenates the specified pubic keys
        /// </summary>
        /// <param name="first"></param>
        /// <param name="second"></param>
        /// <returns></returns>
        public static byte[] Concat(byte[] first, byte[] second)
        {
            Guard.NotNull(first, nameof(first));
            Guard.NotLessThanOrEqualTo(first.Length, 0, nameof(first));
            Guard.NotNull(second, nameof(second));
            Guard.NotLessThanOrEqualTo(second.Length, 0, nameof(second));

            var ret = new byte[first.Length + second.Length];
            Buffer.BlockCopy(first, 0, ret, 0, first.Length);
            Buffer.BlockCopy(second, 0, ret, first.Length, second.Length);
            return ret;
        }

        /// <summary>
        ///     SAH3 hash of [data].
        /// </summary>
        /// <param name="data"></param>
        /// <returns></returns>
        private byte[] Sha3(byte[] data)
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
        private byte[] Sha256(byte[] data)
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