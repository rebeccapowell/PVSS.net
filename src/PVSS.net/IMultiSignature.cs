// // -----------------------------------------------------------------------
// // <copyright file="IMultiSignature.cs" company="Rebecca Powell" year="2020">
// //      All rights are reserved. Reproduction or transmission in whole or
// //      in part, in any form or by any means, electronic, mechanical or
// //      otherwise, is prohibited without the prior written consent of the
// //      copyright owner.
// // </copyright>
// // <summary>
// //      Definition of the IMultiSignature.cs class.
// // </summary>
// // -----------------------------------------------------------------------

using System.Collections.Generic;

namespace PVSS.net
{
    public interface IMultiSignature
    {
        byte[] ComputeCommitmentSecret();

        byte[] ComputeCommitment(byte[] commitmentSecret);

        byte[] ComputeCommitmentHash(byte[] commitment);

        bool ValidateCommitment(byte[] commitment, byte[] commitmentHash);

        byte[] AggregateCommitments(List<byte[]> commitments, long bitmapCommitments);

        byte[] ComputeChallenge(List<byte[]> signers, byte[] publicKey, byte[] aggregatedCommitment, byte[] message,
            long bitmapCommitments);

        byte[] ComputeSignatureShare(byte[] challenge, byte[] privateKey, byte[] commitmentSecret);

        bool VerifySignatureShare(List<byte[]> publicKeys, byte[] publicKey, byte[] signature, byte[] aggCommitment,
            byte[] commitment, byte[] message, long bitmap);

        byte[] AggregateSignatures(List<byte[]> signatureShares, long bitmapSigners);

        bool VerifyAggregatedSignature(List<byte[]> signers, byte[] aggregatedSignature, byte[] aggregatedCommitment,
            byte[] message, long bitmapSigners);
    }
}