using System;
using System.Collections.Generic;
using System.Text;

namespace PVSS.net
{
	public interface IMultiSignatureService
    {
        byte[] ComputeCommitmentSecret();

        byte[] ComputeCommitment(byte[] commitmentSecret);

        byte[] ComputeCommitmentHash(byte[] commitment);

        bool ValidateCommitment(byte[] commitment, byte[] commitmentHash);

        byte[] AggregateCommitments(List<byte[]> commitments, long bitmapCommitments);

        // compute or get the challenge from leader
        byte[] ComputeChallenge(List<byte[]> signers, byte[] publicKey, byte[] aggregatedCommitment, byte[] message, long bitmapCommitments);

        byte[] ComputeSignatureShare(byte[] challenge, byte[] privateKey, byte[] commitmentSecret);

        bool VerifySignatureShare(List<byte[]> publicKeys, byte[] publicKey, byte[] signature, byte[] aggCommitment, byte[] commitment, byte[] message, long bitmap);

        byte[] AggregateSignatures(List<byte[]> signatureShares, long bitmapSigners);

        bool VerifyAggregatedSignature(List<byte[]> signers, byte[] aggregatedSignature, byte[] aggregatedCommitment, byte[] message, long bitmapSigners);
    }
}
