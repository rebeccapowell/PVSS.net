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
                // ReSharper disable once ExpressionIsAlwaysNull
                Assert.Throws<ArgumentNullException>(() => signatureService.ComputeCommitment(commitmentSecret));
            Assert.IsTrue(exception.Message.StartsWith("[commitmentSecret] cannot be Null."));
        }

        [Test]
        public void TestComputeCommitmentEmptySecret()
        {
            var signatureService = new MultiSignature(_sepSecp256K1);
            var commitmentSecret = new byte[0];
            var exception = Assert.Throws<ArgumentOutOfRangeException>(() => signatureService.ComputeCommitment(commitmentSecret));
            Assert.IsTrue(exception.Message.StartsWith("[commitmentSecret] cannot be less than or equal to 0."));
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
                // ReSharper disable once ExpressionIsAlwaysNull
                Assert.Throws<ArgumentNullException>(() => signatureService.AggregateCommitments(commitments, bitmap));
            Console.WriteLine(exception.Message);
            Assert.IsTrue(exception.Message.StartsWith("[commitments] cannot be Null."));
        }

        [Test]
        public void TestAggregateCommitmentsEmptyCommitments()
        {
            var signatureService = new MultiSignature(_sepSecp256K1);
            long bitmap = 3;
            var commitments = new List<byte[]>();

            var exception = Assert.Throws<ArgumentOutOfRangeException>(() => signatureService.AggregateCommitments(commitments, bitmap));
            Console.WriteLine(exception.Message);
            Assert.IsTrue(exception.Message.StartsWith("[commitments] cannot be less than or equal to 0."));
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

        
        [Test]
        public void TestComputeChallengeNullPublicKeys()
        {
            var signatureService = new MultiSignature(_sepSecp256K1);
            long bitmap = 0b111;
            List<byte[]> publicKeys = null;

            var keyPair = new Participant("Alice");
            var publicKey = keyPair.PublicKey;
            var commitments = new List<byte[]>
            {
                "02181b4df800671642e3df9a953a29a4f571acc1bf0714ed5ae714a9804d97079f".ToByteArray(),
                "02e8196913323fbb7a34d9455b778e877e1d1fa0205b5949504e55a2d999931366".ToByteArray(),
                "02ef67409f09053060e79d8ad5b1fe60690b5eaa35b67f071ca111a0a7edeb6b38".ToByteArray()
            };

            var aggregatedCommitment = signatureService.AggregateCommitments(commitments, bitmap);

            var exception = Assert.Throws<ArgumentNullException>(() => 
                signatureService.ComputeChallenge(publicKeys, publicKey, aggregatedCommitment, "hello".ToHexEncodedByteArray(), bitmap));
            Console.WriteLine(exception.Message);
            Assert.IsTrue(exception.Message.StartsWith("[signers] cannot be Null."));
        }

        [Test]
        public void TestComputeChallengeEmptyPublicKeys()
        {
            var signatureService = new MultiSignature(_sepSecp256K1);
            long bitmap = 0b111;
            List<byte[]> publicKeys = new List<byte[]>();

            var keyPair = new Participant("Alice");
            var publicKey = keyPair.PublicKey;
            var commitments = new List<byte[]>
            {
                "02181b4df800671642e3df9a953a29a4f571acc1bf0714ed5ae714a9804d97079f".ToByteArray(),
                "02e8196913323fbb7a34d9455b778e877e1d1fa0205b5949504e55a2d999931366".ToByteArray(),
                "02ef67409f09053060e79d8ad5b1fe60690b5eaa35b67f071ca111a0a7edeb6b38".ToByteArray()
            };

            var aggregatedCommitment = signatureService.AggregateCommitments(commitments, bitmap);

            var exception = Assert.Throws<ArgumentOutOfRangeException>(() =>
                signatureService.ComputeChallenge(publicKeys, publicKey, aggregatedCommitment, "hello".ToHexEncodedByteArray(), bitmap));
            Console.WriteLine(exception.Message);
            Assert.IsTrue(exception.Message.StartsWith("[signers] cannot be less than or equal to 0."));
        }

        [Test]
        public void TestComputeChallengeNullPublicKey()
        {
            var signatureService = new MultiSignature(_sepSecp256K1);
            long bitmap = 0b111;
            List<byte[]> publicKeys = new List<byte[]>();
            byte[] publicKey = null;

            var commitments = new List<byte[]>
            {
                "02181b4df800671642e3df9a953a29a4f571acc1bf0714ed5ae714a9804d97079f".ToByteArray(),
                "02e8196913323fbb7a34d9455b778e877e1d1fa0205b5949504e55a2d999931366".ToByteArray(),
                "02ef67409f09053060e79d8ad5b1fe60690b5eaa35b67f071ca111a0a7edeb6b38".ToByteArray(),
                new Participant("Commitment").PublicKey
            };

            var aggregatedCommitment = signatureService.AggregateCommitments(commitments, bitmap);

            var exception = Assert.Throws<ArgumentOutOfRangeException>(() =>
                signatureService.ComputeChallenge(publicKeys, publicKey, aggregatedCommitment, "hello".ToHexEncodedByteArray(), bitmap));
            Console.WriteLine(exception.Message);
            Assert.IsTrue(exception.Message.StartsWith("[signers] cannot be less than or equal to 0."));
        }

        [Test]
        public void TestComputeChallengeNullAggregatedCommitment()
        {
            var signatureService = new MultiSignature(_sepSecp256K1);
            long bitmap = 0b111;
            List<byte[]> publicKeys = new List<byte[]>();
            byte[] publicKey = new Participant("Alice").PublicKey;

            var commitments = new List<byte[]>
            {
                "02181b4df800671642e3df9a953a29a4f571acc1bf0714ed5ae714a9804d97079f".ToByteArray(),
                "02e8196913323fbb7a34d9455b778e877e1d1fa0205b5949504e55a2d999931366".ToByteArray(),
                "02ef67409f09053060e79d8ad5b1fe60690b5eaa35b67f071ca111a0a7edeb6b38".ToByteArray(),
                new Participant("Commitment 1").PublicKey,
                new Participant("Commitment 2").PublicKey,
                publicKey
            };


            byte[] aggregatedCommitment = null;

            var exception = Assert.Throws<ArgumentOutOfRangeException>(() =>
                signatureService.ComputeChallenge(publicKeys, publicKey, aggregatedCommitment, "hello".ToHexEncodedByteArray(), bitmap));
            Console.WriteLine(exception.Message);
            Assert.IsTrue(exception.Message.StartsWith("[signers] cannot be less than or equal to 0."));
        }

        [Test]
        public void TestComputeChallengeEmptyAggregatedCommitment()
        {
            var signatureService = new MultiSignature(_sepSecp256K1);
            long bitmap = 0b111;
            List<byte[]> publicKeys = new List<byte[]>();
            byte[] publicKey = new Participant("Alice").PublicKey;

            var commitments = new List<byte[]>
            {
                "02181b4df800671642e3df9a953a29a4f571acc1bf0714ed5ae714a9804d97079f".ToByteArray(),
                "02e8196913323fbb7a34d9455b778e877e1d1fa0205b5949504e55a2d999931366".ToByteArray(),
                "02ef67409f09053060e79d8ad5b1fe60690b5eaa35b67f071ca111a0a7edeb6b38".ToByteArray(),
                new Participant("Commitment 1").PublicKey,
                new Participant("Commitment 2").PublicKey,
                publicKey
            };


            byte[] aggregatedCommitment = new byte[0];

            var exception = Assert.Throws<ArgumentOutOfRangeException>(() =>
                signatureService.ComputeChallenge(publicKeys, publicKey, aggregatedCommitment, "hello".ToHexEncodedByteArray(), bitmap));
            Console.WriteLine(exception.Message);
            Assert.IsTrue(exception.Message.StartsWith("[signers] cannot be less than or equal to 0."));
        }

        [Test]
        public void TestComputeChallengeNullMessage()
        {
            var signatureService = new MultiSignature(_sepSecp256K1);
            long bitmap = 0b111;
            List<byte[]> publicKeys = new List<byte[]>();
            byte[] publicKey = new Participant("Alice").PublicKey;
            byte[] message = null;

            var commitments = new List<byte[]>
            {
                "02181b4df800671642e3df9a953a29a4f571acc1bf0714ed5ae714a9804d97079f".ToByteArray(),
                "02e8196913323fbb7a34d9455b778e877e1d1fa0205b5949504e55a2d999931366".ToByteArray(),
                "02ef67409f09053060e79d8ad5b1fe60690b5eaa35b67f071ca111a0a7edeb6b38".ToByteArray(),
                new Participant("Commitment 1").PublicKey,
                new Participant("Commitment 2").PublicKey,
                publicKey
            };


            byte[] aggregatedCommitment = new byte[0];

            var exception = Assert.Throws<ArgumentOutOfRangeException>(() =>
                // ReSharper disable once ExpressionIsAlwaysNull
                signatureService.ComputeChallenge(publicKeys, publicKey, aggregatedCommitment, message, bitmap));
            Console.WriteLine(exception.Message);
            Assert.IsTrue(exception.Message.StartsWith("[signers] cannot be less than or equal to 0."));
        }

        [Test]
        public void TestComputeChallengeEmptyMessage()
        {
            var signatureService = new MultiSignature(_sepSecp256K1);
            long bitmap = 0b111;
            List<byte[]> publicKeys = new List<byte[]>();
            byte[] publicKey = new Participant("Alice").PublicKey;

            var commitments = new List<byte[]>
            {
                "02181b4df800671642e3df9a953a29a4f571acc1bf0714ed5ae714a9804d97079f".ToByteArray(),
                "02e8196913323fbb7a34d9455b778e877e1d1fa0205b5949504e55a2d999931366".ToByteArray(),
                "02ef67409f09053060e79d8ad5b1fe60690b5eaa35b67f071ca111a0a7edeb6b38".ToByteArray(),
                new Participant("Commitment 1").PublicKey,
                new Participant("Commitment 2").PublicKey,
                publicKey
            };


            byte[] aggregatedCommitment = new byte[0];

            var exception = Assert.Throws<ArgumentOutOfRangeException>(() =>
                signatureService.ComputeChallenge(publicKeys, publicKey, aggregatedCommitment, string.Empty.ToHexEncodedByteArray(), bitmap));
            Console.WriteLine(exception.Message);
            Assert.IsTrue(exception.Message.StartsWith("[signers] cannot be less than or equal to 0."));
        }

        [Test]
        public void TestComputeSignatureShareNullChallenge()
        {
            var signatureService = new MultiSignature(_sepSecp256K1);
            byte[] challenge = null;
            byte[] privateKey = new Participant("Alice").PrivateKey;
            byte[] commitmentSecret = signatureService.ComputeCommitmentSecret();

            var exception = Assert.Throws<ArgumentNullException>(() =>
                signatureService.ComputeSignatureShare(challenge, privateKey, commitmentSecret));
            Console.WriteLine(exception.Message);
            Assert.IsTrue(exception.Message.StartsWith("[challenge] cannot be Null."));
        }

        [Test]
        public void TestComputeSignatureShareEmptyChallenge()
        {
            var signatureService = new MultiSignature(_sepSecp256K1);
            byte[] challenge = new byte[0];
            byte[] privateKey = new Participant("Alice").PrivateKey;
            byte[] commitmentSecret = signatureService.ComputeCommitmentSecret();

            var exception = Assert.Throws<ArgumentOutOfRangeException>(() =>
                signatureService.ComputeSignatureShare(challenge, privateKey, commitmentSecret));
            Console.WriteLine(exception.Message);
            Assert.IsTrue(exception.Message.StartsWith("[challenge] cannot be less than or equal to 0."));
        }

        [Test]
        public void TestComputeSignatureShareNullPrivateKey()
        {
            var signatureService = new MultiSignature(_sepSecp256K1);
            byte[] challenge = Digests.Sha3("dummy challenge".ToHexEncodedByteArray());
            byte[] privateKey = null;
            byte[] commitmentSecret = signatureService.ComputeCommitmentSecret();

            var exception = Assert.Throws<ArgumentNullException>(() => 
                signatureService.ComputeSignatureShare(challenge, privateKey, commitmentSecret));
            Console.WriteLine(exception.Message);
            Assert.IsTrue(exception.Message.StartsWith("[privateKey] cannot be Null."));
        }

        [Test]
        public void TestComputeSignatureShareEmptyPrivateKey()
        {
            var signatureService = new MultiSignature(_sepSecp256K1);
            byte[] commitmentSecret = signatureService.ComputeCommitmentSecret();
            byte[] challenge = Digests.Sha3("dummy challenge".ToHexEncodedByteArray());
            byte[] privateKey = new byte[0];

            var exception = Assert.Throws<ArgumentOutOfRangeException>(() => 
                signatureService.ComputeSignatureShare(challenge, privateKey, commitmentSecret));
            Console.WriteLine(exception.Message);
            Assert.IsTrue(exception.Message.StartsWith("[privateKey] cannot be less than or equal to 0."));
        }

        [Test]
        public void TestComputeSignatureShareNullCommitmentSecret()
        {
            var signatureService = new MultiSignature(_sepSecp256K1);
            byte[] challenge = Digests.Sha3("dummy challenge".ToHexEncodedByteArray());
            byte[] privateKey = new Participant("Alice").PrivateKey;
            byte[] commitmentSecret = null;

            var exception = Assert.Throws<ArgumentNullException>(() => 
                signatureService.ComputeSignatureShare(challenge, privateKey, commitmentSecret));
            Console.WriteLine(exception.Message);
            Assert.IsTrue(exception.Message.StartsWith("[commitmentSecret] cannot be Null."));
        }

        [Test]
        public void TestComputeSignatureShareEmptyCommitmentSecret()
        {
            var signatureService = new MultiSignature(_sepSecp256K1);
            byte[] commitmentSecret = new byte[0];
            byte[] challenge = Digests.Sha3("dummy challenge".ToHexEncodedByteArray());
            byte[] privateKey = new Participant("Alice").PrivateKey;

            var exception = Assert.Throws<ArgumentOutOfRangeException>(() => 
                signatureService.ComputeSignatureShare(challenge, privateKey, commitmentSecret));
            Console.WriteLine(exception.Message);
            Assert.IsTrue(exception.Message.StartsWith("[commitmentSecret] cannot be less than or equal to 0."));
        }

        [Test]
        public void TestVerifySignatureShareOk()
        {
            var signatureService = new MultiSignature(_sepSecp256K1);
            var signers = new List<byte[]>();
            var commitmentSecrets = new List<byte[]>();
            var commitments = new List<byte[]>();

            var alice = new Participant("Alice");
            var bob = new Participant("Bob");
            var carol = new Participant("Carol");

            long bitmap = 0;
            var message = "The quick brown fox jumps over the lazy dog.".ToHexEncodedByteArray();

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