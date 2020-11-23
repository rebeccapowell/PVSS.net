# PVSS.net
This is a test project. It is not production ready and is unlilely to ever be. You have been warned.

# Multi Signature
- Implementation of Belare and Neven Multi-signature
- See ["Multi-Signatures in the Plain Public-Key Model and a General Forking Lemma"](https://cseweb.ucsd.edu/~mihir/papers/multisignatures-ccs.pdf)
- Rough port of [Java implementation](https://github.com/ElrondNetwork/elrond-node-prototype/blob/master/elrond-core/)

# Usage
See [MultiSignaureTest](https://github.com/rebeccapowell/PVSS.net/blob/main/src/PVSS.Net.Tests/MultisignatureTest.cs)

```
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
```

