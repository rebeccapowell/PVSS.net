// // -----------------------------------------------------------------------
// // <copyright file="UnitTest1.cs" company="Rebecca Powell" year="2020">
// //      All rights are reserved. Reproduction or transmission in whole or
// //      in part, in any form or by any means, electronic, mechanical or
// //      otherwise, is prohibited without the prior written consent of the
// //      copyright owner.
// // </copyright>
// // <summary>
// //      Definition of the UnitTest1.cs class.
// // </summary>
// // -----------------------------------------------------------------------

using System;
using System.Collections.Generic;
using System.Linq;
using NUnit.Framework;
using Org.BouncyCastle.Math;
using PVSS.net;
using PVSS.net.Extensions;

namespace PVSS.Net.Tests
{
    public class Tests
    {
        private ISecp256k1 _sepSecp256K1;

        [SetUp]
        public void Setup()
        {
            _sepSecp256K1 = new Secp256k1();
        }

        [Test]
        public void TestComputeCommitmentSecretNotZero()
        {
            var signatureService = new MultiSignature(_sepSecp256K1);
            var commitmentSecret = signatureService.ComputeCommitmentSecret();
            var secret = new BigInteger(commitmentSecret);

            Assert.AreNotEqual(BigInteger.Zero, secret);
        }

        [Test]
        public void TestComputeCommitmentNullSecret()
        {
            var signatureService = new MultiSignature(_sepSecp256K1);
            byte[] commitmentSecret = null;

            var exception =
                Assert.Throws<NullReferenceException>(() => signatureService.ComputeCommitment(commitmentSecret));
        }

        [Test]
        public void TestComputeCommitmentEmptySecret()
        {
            var signatureService = new MultiSignature(_sepSecp256K1);
            var commitmentSecret = new byte[0];
            var exception = Assert.Throws<FormatException>(() => signatureService.ComputeCommitment(commitmentSecret));
        }

        [Test]
        public void TestComputeCommitmentHash()
        {
            var signatureService = new MultiSignature(_sepSecp256K1);
            var commitment = signatureService.ComputeCommitment(signatureService.ComputeCommitmentSecret());
            var commitmentHash = signatureService.ComputeCommitmentHash(commitment);

            Assert.AreNotEqual(commitment, commitmentHash);
        }

        [Test]
        public void TestValidateCommitmentValid()
        {
            var signatureService = new MultiSignature(_sepSecp256K1);
            var commitment = signatureService.ComputeCommitment(signatureService.ComputeCommitmentSecret());
            var commitmentHash = signatureService.ComputeCommitmentHash(commitment);

            Assert.IsTrue(signatureService.ValidateCommitment(commitment, commitmentHash));
        }

        [Test]
        public void TestAggregateCommitmentsNullCommitments()
        {
            var signatureService = new MultiSignature(_sepSecp256K1);
            long bitmap = 3;
            List<byte[]> commitments = null;

            var exception =
                Assert.Throws<NullReferenceException>(() => signatureService.AggregateCommitments(commitments, bitmap));
        }

        public void TestAggregateCommitmentsEmptyCommitments()
        {
            var signatureService = new MultiSignature(_sepSecp256K1);
            long bitmap = 3;
            var commitments = new List<byte[]>();

            var exception = Assert.Throws<Exception>(() => signatureService.AggregateCommitments(commitments, bitmap));
        }

        [Test]
        public void TestAggregatedCommitment()
        {
            var signatureService = new MultiSignature(_sepSecp256K1);
            long bitmap = 0b111;
            var commitments = new List<byte[]>
            {
                "02181b4df800671642e3df9a953a29a4f571acc1bf0714ed5ae714a9804d97079f".ToByteArray(),
                "02e8196913323fbb7a34d9455b778e877e1d1fa0205b5949504e55a2d999931366".ToByteArray(),
                "02ef67409f09053060e79d8ad5b1fe60690b5eaa35b67f071ca111a0a7edeb6b38".ToByteArray()
            };


            Assert.AreEqual("02534d4371d6ea9f8b856a632e4e31d784eec9120b3252080702d872c696012289",
                signatureService.AggregateCommitments(commitments, bitmap).ToHexString());
        }

        /*
         *@Test(expected = IllegalArgumentException.class)
    public void testComputeChallengeNullPublicKeys() {
        MultiSignatureService signatureService = AppServiceProvider.getMultiSignatureService();
        long bitmap = 0b111;
        ArrayList<byte[]> publicKeys = null;
        byte[] publicKey = new PublicKey(new PrivateKey()).getValue();
        ArrayList<byte[]> commitments = new ArrayList<>();
        byte[] aggregatedCommitment;
        commitments.add(Util.hexStringToByteArray("02181b4df800671642e3df9a953a29a4f571acc1bf0714ed5ae714a9804d97079f"));
        commitments.add(Util.hexStringToByteArray("02e8196913323fbb7a34d9455b778e877e1d1fa0205b5949504e55a2d999931366"));
        commitments.add(Util.hexStringToByteArray("02ef67409f09053060e79d8ad5b1fe60690b5eaa35b67f071ca111a0a7edeb6b38"));

        aggregatedCommitment = signatureService.aggregateCommitments(commitments, bitmap);
        signatureService.computeChallenge(publicKeys, publicKey, aggregatedCommitment, "hello".getBytes(), bitmap);
    }

    @Test(expected = IllegalArgumentException.class)
    public void testComputeChallengeEmptyPublicKeys() {
        MultiSignatureService signatureService = AppServiceProvider.getMultiSignatureService();
        long bitmap = 0b111;
        ArrayList<byte[]> publicKeys = new ArrayList<>();
        byte[] publicKey = new PublicKey(new PrivateKey()).getValue();
        ArrayList<byte[]> commitments = new ArrayList<>();
        byte[] aggregatedCommitment;
        commitments.add(Util.hexStringToByteArray("02181b4df800671642e3df9a953a29a4f571acc1bf0714ed5ae714a9804d97079f"));
        commitments.add(Util.hexStringToByteArray("02e8196913323fbb7a34d9455b778e877e1d1fa0205b5949504e55a2d999931366"));
        commitments.add(Util.hexStringToByteArray("02ef67409f09053060e79d8ad5b1fe60690b5eaa35b67f071ca111a0a7edeb6b38"));

        aggregatedCommitment = signatureService.aggregateCommitments(commitments, bitmap);
        signatureService.computeChallenge(publicKeys, publicKey, aggregatedCommitment, "hello".getBytes(), bitmap);
    }

    @Test(expected = IllegalArgumentException.class)
    public void testComputeChallengeNullPublicKey() {
        MultiSignatureService signatureService = AppServiceProvider.getMultiSignatureService();
        long bitmap = 0b111;
        ArrayList<byte[]> publicKeys = new ArrayList<>();
        byte[] publicKey = null;
        ArrayList<byte[]> commitments = new ArrayList<>();
        byte[] aggregatedCommitment;

        commitments.add(Util.hexStringToByteArray("02181b4df800671642e3df9a953a29a4f571acc1bf0714ed5ae714a9804d97079f"));
        commitments.add(Util.hexStringToByteArray("02e8196913323fbb7a34d9455b778e877e1d1fa0205b5949504e55a2d999931366"));
        commitments.add(Util.hexStringToByteArray("02ef67409f09053060e79d8ad5b1fe60690b5eaa35b67f071ca111a0a7edeb6b38"));
        publicKeys.add(new PublicKey(new PrivateKey()).getValue());
        aggregatedCommitment = signatureService.aggregateCommitments(commitments, bitmap);

        signatureService.computeChallenge(publicKeys, publicKey, aggregatedCommitment, "hello".getBytes(), bitmap);
    }

    @Test(expected = IllegalArgumentException.class)
    public void testComputeChallengeNullAggregatedCommitment() {
        MultiSignatureService signatureService = AppServiceProvider.getMultiSignatureService();
        long bitmap = 0b111;
        ArrayList<byte[]> publicKeys = new ArrayList<>();
        byte[] publicKey = new PublicKey(new PrivateKey()).getValue();
        ArrayList<byte[]> commitments = new ArrayList<>();
        byte[] aggregatedCommitment;

        commitments.add(Util.hexStringToByteArray("02181b4df800671642e3df9a953a29a4f571acc1bf0714ed5ae714a9804d97079f"));
        commitments.add(Util.hexStringToByteArray("02e8196913323fbb7a34d9455b778e877e1d1fa0205b5949504e55a2d999931366"));
        commitments.add(Util.hexStringToByteArray("02ef67409f09053060e79d8ad5b1fe60690b5eaa35b67f071ca111a0a7edeb6b38"));
        publicKeys.add(new PublicKey(new PrivateKey()).getValue());
        publicKeys.add(new PublicKey((new PrivateKey())).getValue());
        publicKeys.add(publicKey);
        aggregatedCommitment = null;

        signatureService.computeChallenge(publicKeys, publicKey, aggregatedCommitment, "hello".getBytes(), bitmap);
    }

    @Test(expected = IllegalArgumentException.class)
    public void testComputeChallengeEmptyAggregatedCommitment() {
        MultiSignatureService signatureService = AppServiceProvider.getMultiSignatureService();
        long bitmap = 0b111;
        ArrayList<byte[]> publicKeys = new ArrayList<>();
        byte[] publicKey = new PublicKey(new PrivateKey()).getValue();
        ArrayList<byte[]> commitments = new ArrayList<>();
        byte[] aggregatedCommitment = new byte[0];

        commitments.add(Util.hexStringToByteArray("02181b4df800671642e3df9a953a29a4f571acc1bf0714ed5ae714a9804d97079f"));
        commitments.add(Util.hexStringToByteArray("02e8196913323fbb7a34d9455b778e877e1d1fa0205b5949504e55a2d999931366"));
        commitments.add(Util.hexStringToByteArray("02ef67409f09053060e79d8ad5b1fe60690b5eaa35b67f071ca111a0a7edeb6b38"));
        publicKeys.add(new PublicKey(new PrivateKey()).getValue());
        publicKeys.add(new PublicKey((new PrivateKey())).getValue());
        publicKeys.add(publicKey);

        signatureService.computeChallenge(publicKeys, publicKey, aggregatedCommitment, "hello".getBytes(), bitmap);
    }

    @Test(expected = IllegalArgumentException.class)
    public void testComputeChallengeNullMessage() {
        MultiSignatureService signatureService = AppServiceProvider.getMultiSignatureService();
        long bitmap = 0b111;
        ArrayList<byte[]> publicKeys = new ArrayList<>();
        byte[] publicKey = new PublicKey(new PrivateKey()).getValue();
        ArrayList<byte[]> commitments = new ArrayList<>();
        byte[] aggregatedCommitment;
        byte[] message = null;

        commitments.add(Util.hexStringToByteArray("02181b4df800671642e3df9a953a29a4f571acc1bf0714ed5ae714a9804d97079f"));
        commitments.add(Util.hexStringToByteArray("02e8196913323fbb7a34d9455b778e877e1d1fa0205b5949504e55a2d999931366"));
        commitments.add(Util.hexStringToByteArray("02ef67409f09053060e79d8ad5b1fe60690b5eaa35b67f071ca111a0a7edeb6b38"));
        publicKeys.add(new PublicKey(new PrivateKey()).getValue());
        publicKeys.add(new PublicKey((new PrivateKey())).getValue());
        publicKeys.add(publicKey);

        aggregatedCommitment = signatureService.aggregateCommitments(commitments, bitmap);
        signatureService.computeChallenge(publicKeys, publicKey, aggregatedCommitment, message, bitmap);
    }

    @Test(expected = IllegalArgumentException.class)
    public void testComputeChallengeEmptyMessage() {
        MultiSignatureService signatureService = AppServiceProvider.getMultiSignatureService();
        long bitmap = 0b111;
        ArrayList<byte[]> publicKeys = new ArrayList<>();
        byte[] publicKey = new PublicKey(new PrivateKey()).getValue();
        ArrayList<byte[]> commitments = new ArrayList<>();
        byte[] aggregatedCommitment;
        byte[] message = "".getBytes();

        commitments.add(Util.hexStringToByteArray("02181b4df800671642e3df9a953a29a4f571acc1bf0714ed5ae714a9804d97079f"));
        commitments.add(Util.hexStringToByteArray("02e8196913323fbb7a34d9455b778e877e1d1fa0205b5949504e55a2d999931366"));
        commitments.add(Util.hexStringToByteArray("02ef67409f09053060e79d8ad5b1fe60690b5eaa35b67f071ca111a0a7edeb6b38"));
        publicKeys.add(new PublicKey(new PrivateKey()).getValue());
        publicKeys.add(new PublicKey((new PrivateKey())).getValue());
        publicKeys.add(publicKey);

        aggregatedCommitment = signatureService.aggregateCommitments(commitments, bitmap);
        signatureService.computeChallenge(publicKeys, publicKey, aggregatedCommitment, message, bitmap);
    }

    @Test(expected = IllegalArgumentException.class)
    public void testComputeSignatureShareNullChallenge() {
        MultiSignatureService signatureService = AppServiceProvider.getMultiSignatureService();
        byte[] challenge = null;
        byte[] privateKey = new PrivateKey().getValue();
        byte[] commitmentSecret = signatureService.computeCommitmentSecret();

        signatureService.computeSignatureShare(challenge, privateKey, commitmentSecret);
    }

    @Test(expected = IllegalArgumentException.class)
    public void testComputeSignatureShareEmptyChallenge() {
        MultiSignatureService signatureService = AppServiceProvider.getMultiSignatureService();
        byte[] challenge = new byte[0];
        byte[] privateKey = new PrivateKey().getValue();
        byte[] commitmentSecret = signatureService.computeCommitmentSecret();

        signatureService.computeSignatureShare(challenge, privateKey, commitmentSecret);
    }

    @Test(expected = IllegalArgumentException.class)
    public void testComputeSignatureShareNullPrivateKey() {
        MultiSignatureService signatureService = AppServiceProvider.getMultiSignatureService();
        byte[] challenge = Util.SHA3.get().digest("dummy challenge".getBytes());
        byte[] privateKey = null;
        byte[] commitmentSecret = signatureService.computeCommitmentSecret();

        signatureService.computeSignatureShare(challenge, privateKey, commitmentSecret);
    }

    @Test(expected = IllegalArgumentException.class)
    public void testComputeSignatureShareEmptyPrivateKey() {
        MultiSignatureService signatureService = AppServiceProvider.getMultiSignatureService();
        byte[] commitmentSecret = signatureService.computeCommitmentSecret();
        byte[] challenge = Util.SHA3.get().digest("dummy challenge".getBytes());
        byte[] privateKey = new byte[0];

        signatureService.computeSignatureShare(challenge, privateKey, commitmentSecret);
    }

    @Test(expected = IllegalArgumentException.class)
    public void testComputeSignatureShareNullCommitmentSecret() {
        MultiSignatureService signatureService = AppServiceProvider.getMultiSignatureService();
        byte[] challenge = Util.SHA3.get().digest("dummy challenge".getBytes());
        byte[] privateKey = new PrivateKey().getValue();;
        byte[] commitmentSecret = null;

        signatureService.computeSignatureShare(challenge, privateKey, commitmentSecret);
    }

    @Test(expected = IllegalArgumentException.class)
    public void testComputeSignatureShareEmptyCommitmentSecret() {
        MultiSignatureService signatureService = AppServiceProvider.getMultiSignatureService();
        byte[] commitmentSecret = new byte[0];
        byte[] challenge = Util.SHA3.get().digest("dummy challenge".getBytes());
        byte[] privateKey = new PrivateKey().getValue();

        signatureService.computeSignatureShare(challenge, privateKey, commitmentSecret);
    }
         *
         *
         */

        [Test]
        public void TestVerifySignatureShareOK()
        {
            var signatureService = new MultiSignature(_sepSecp256K1);
            var signers = new List<byte[]>();
            var commitmentSecrets = new List<byte[]>();
            var commitments = new List<byte[]>();

            var alice = new Participant("Alice");
            var bob = new Participant("Bob");
            var carol = new Participant("Carol");

            long bitmap = 0;
            var message = string
                .Concat("The quick brown fox jumps over the lazy dog.".Select(x => ((int) x).ToString("x")))
                .ToByteArray();

            signers.Add(alice.PublicKey);
            signers.Add(bob.PublicKey);
            signers.Add(carol.PublicKey);

            for (var i = 0; i < signers.Count; i++)
            {
                bitmap = (bitmap << 1) | 1;
                commitmentSecrets.Add(signatureService.ComputeCommitmentSecret());
                commitments.Add(signatureService.ComputeCommitment(commitmentSecrets[i]));
            }

            var aggregatedCommitment = signatureService.AggregateCommitments(commitments, bitmap);
            var challenge =
                signatureService.ComputeChallenge(signers, alice.PublicKey, aggregatedCommitment, message, bitmap);
            var signature = signatureService.ComputeSignatureShare(challenge, alice.PrivateKey, commitmentSecrets[0]);

            Assert.IsTrue(signatureService.VerifySignatureShare(
                signers,
                alice.PublicKey,
                signature,
                aggregatedCommitment,
                commitments[0],
                message,
                bitmap));
        }
    }
}