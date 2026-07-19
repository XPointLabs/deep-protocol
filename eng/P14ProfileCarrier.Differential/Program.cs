using System.Security.Cryptography;
using Deep.Protocol.DeepExtension.Membership;
using Deep.Protocol.DeepExtension.SelfHostedProfiles;
using XNode.ProfileGenerator;
using XNode.ProfileGenerator.Tests;

const string ExpectedSha256 =
    "cc8df0559b033ad7c70aa5d19134c06c58fb2dd6cfc10449525e1fb919679dbe";

var xnodeInput = TestOnlyProfileFixture.Input();
var xnodeOptions = TestOnlyProfileFixture.Options();
var scheme = TestOnlyProfileFixture.SignatureScheme();
var xnode = DormantProfileComposer.Compose(xnodeInput, xnodeOptions, scheme);

var deepInput = new ProfileCarrierAssemblyInput(
    xnodeInput.CanonicalGenesis,
    xnodeInput.GenesisSignatures.Select(static signature => new MembershipSignature
    {
        SignerId = signature.SignerId,
        Domain = signature.Domain,
        Signature = signature.Signature
    }),
    xnodeInput.CanonicalSignedDelegation,
    xnodeInput.CanonicalSignedBridges);
var deepOptions = new ProfileCarrierVerificationOptions(
    xnodeOptions.VerificationTimeUnixSeconds,
    xnodeOptions.AllowedClockSkewSeconds,
    xnodeOptions.Protocol);
var deep = ProfileCarrierComposer.ComposeExact(deepInput, deepOptions, scheme);

if (!xnode.FilePayload.Span.SequenceEqual(deep.FilePayload.Span))
{
    throw new InvalidOperationException("Pinned XNode and Deep carrier bytes differ.");
}

var actual = Convert.ToHexStringLower(SHA256.HashData(deep.FilePayload.Span));
if (!StringComparer.Ordinal.Equals(ExpectedSha256, actual))
{
    throw new InvalidOperationException("Differential payload hash differs from the manifest.");
}

Console.WriteLine($"PASS {actual}");
