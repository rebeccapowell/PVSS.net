# PVSS.net
This is a test project. It is not production ready and is unlilely to ever be. You have been warned.

## Multi Signature
- Implementation of Belare and Neven Multi-signature
- See ["Multi-Signatures in the Plain Public-Key Model and a General Forking Lemma"](https://cseweb.ucsd.edu/~mihir/papers/multisignatures-ccs.pdf)
- Rough port of [Java implementation](https://github.com/ElrondNetwork/elrond-node-prototype/blob/master/elrond-core/)

## Usage
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

## Next Steps
- [Publicly Verifiable Secret Sharing](https://www.ubilab.org/publications/print_versions/pdf/sta96.pdf)
- [MPSS: Mobile Proactive Secret Sharing](http://pmg.lcs.mit.edu/papers/a34-schultz.pdf)
- To do....

## Other interesting papers worth considering:
- [Publicly Verifiable Secret Sharing](https://www.ubilab.org/publications/print_versions/pdf/sta96.pdf)
- [A Practical (Non-interactive) Publicly Verifiable Secret Sharing Scheme](https://eprint.iacr.org/2010/495.pdf)
- [Distributed Key Generation with Ethereum Smart Contracts](https://www.sqi.at/resources/Schindler-2019-CIW-Distributed-Key-Generation-with-Ethereum-Smart-Contracts.pdf)
- [ETHDKG: Distributed Key Generation with Ethereum Smart Contracts](https://eprint.iacr.org/2019/985.pdf)
- [Keeping Time-Release Secrets through Smart Contracts](https://eprint.iacr.org/2018/1166.pdf)
- [On The Applicability Of Secret Sharing Cryptography In Secure Cloud Services](https://repositum.tuwien.at/retrieve/11621)
- [MPSS: Mobile Proactive Secret Sharing](http://pmg.lcs.mit.edu/papers/a34-schultz.pdf)
- [SilentDelivery: Practical Timed-delivery of Private Information using Smart Contracts](https://arxiv.org/pdf/1912.07824.pdf)
- [A Simple Publicly Verifiable Secret Sharing Scheme and its Application to Electronic Voting](https://www.win.tue.nl/~berry/papers/crypto99.pdf)
- [ECDKG: A Distributed Key Generation Protocol Based on Elliptic Curve Discrete Logarithm](https://citeseerx.ist.psu.edu/viewdoc/download?doi=10.1.1.124.4128&rep=rep1&type=pdf)
- [Fast Multiparty Threshold ECDSA with Fast Trustless Setup](https://eprint.iacr.org/2019/114.pdf)


