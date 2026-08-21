using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;
using Deep.Protocol.DeepExtension.CompatibilityEnvelopes;

namespace Deep.Protocol.Tests.Fakes;

/// <summary>
/// Deterministic test double for contract vectors. This is not a cryptographic construction and
/// must never move to a production assembly.
/// </summary>
internal sealed class DeterministicTestCompatibilityEnvelopeCrypto : ICompatibilityEnvelopeCrypto
{
    public List<string> SealDomains { get; } = [];
    public List<string> OpenDomains { get; } = [];

    public CompatibilityEnvelopeSealedResult Seal(CompatibilityEnvelopeSealRequest request)
    {
        SealDomains.Add(request.Domain);
        var recipientKey = SHA256.HashData(request.RecipientKeyMaterial.Span);
        var sender = request.SenderAuthenticationSecret.ToArray();
        var plaintext = request.Plaintext.ToArray();
        var frame = new byte[2 + sender.Length + plaintext.Length];
        BinaryPrimitives.WriteUInt16BigEndian(frame, checked((ushort)sender.Length));
        sender.CopyTo(frame, 2);
        plaintext.CopyTo(frame, 2 + sender.Length);

        var ciphertext = XorWithDeterministicStream(
            frame,
            recipientKey,
            request.Domain,
            request.NonceContext.Span);
        var tag = ComputeTag(
            recipientKey,
            request.Domain,
            request.NonceContext.Span,
            request.AssociatedData.Span,
            ciphertext);

        var sealedBytes = new byte[tag.Length + ciphertext.Length];
        tag.CopyTo(sealedBytes, 0);
        ciphertext.CopyTo(sealedBytes, tag.Length);
        return new CompatibilityEnvelopeSealedResult(sealedBytes);
    }

    public CompatibilityEnvelopeOpenedResult Open(CompatibilityEnvelopeOpenRequest request)
    {
        OpenDomains.Add(request.Domain);
        if (request.Ciphertext.Length < SHA256.HashSizeInBytes + 2)
        {
            throw new CryptographicException("Synthetic ciphertext is truncated.");
        }

        var recipientKey = SHA256.HashData(request.RecipientKeyMaterial.Span);
        var suppliedTag = request.Ciphertext.Span[..SHA256.HashSizeInBytes];
        var ciphertext = request.Ciphertext.Span[SHA256.HashSizeInBytes..];
        var expectedTag = ComputeTag(
            recipientKey,
            request.Domain,
            request.NonceContext.Span,
            request.AssociatedData.Span,
            ciphertext);
        if (!CryptographicOperations.FixedTimeEquals(suppliedTag, expectedTag))
        {
            throw new CryptographicException("Synthetic authentication failed.");
        }

        var frame = XorWithDeterministicStream(
            ciphertext,
            recipientKey,
            request.Domain,
            request.NonceContext.Span);
        var senderLength = BinaryPrimitives.ReadUInt16BigEndian(frame);
        if (senderLength == 0 || senderLength > frame.Length - 2)
        {
            throw new CryptographicException("Synthetic sender frame is malformed.");
        }

        return new CompatibilityEnvelopeOpenedResult(
            frame.AsMemory(2 + senderLength).ToArray(),
            frame.AsMemory(2, senderLength).ToArray());
    }

    private static byte[] XorWithDeterministicStream(
        ReadOnlySpan<byte> input,
        ReadOnlySpan<byte> recipientKey,
        string domain,
        ReadOnlySpan<byte> nonce)
    {
        var output = new byte[input.Length];
        var domainBytes = Encoding.UTF8.GetBytes(domain);
        var offset = 0;
        uint counter = 0;
        while (offset < input.Length)
        {
            var seed = new byte[recipientKey.Length + domainBytes.Length + nonce.Length + 4];
            recipientKey.CopyTo(seed);
            domainBytes.CopyTo(seed.AsSpan(recipientKey.Length));
            nonce.CopyTo(seed.AsSpan(recipientKey.Length + domainBytes.Length));
            BinaryPrimitives.WriteUInt32BigEndian(seed.AsSpan(seed.Length - 4), counter++);
            var block = SHA256.HashData(seed);
            var take = Math.Min(block.Length, input.Length - offset);
            for (var index = 0; index < take; index++)
            {
                output[offset + index] = (byte)(input[offset + index] ^ block[index]);
            }

            offset += take;
        }

        return output;
    }

    private static byte[] ComputeTag(
        byte[] recipientKey,
        string domain,
        ReadOnlySpan<byte> nonce,
        ReadOnlySpan<byte> associatedData,
        ReadOnlySpan<byte> ciphertext)
    {
        var domainBytes = Encoding.UTF8.GetBytes(domain);
        var authenticated = new byte[
            domainBytes.Length +
            nonce.Length +
            associatedData.Length +
            ciphertext.Length];
        var offset = 0;
        domainBytes.CopyTo(authenticated, offset);
        offset += domainBytes.Length;
        nonce.CopyTo(authenticated.AsSpan(offset));
        offset += nonce.Length;
        associatedData.CopyTo(authenticated.AsSpan(offset));
        offset += associatedData.Length;
        ciphertext.CopyTo(authenticated.AsSpan(offset));
        return HMACSHA256.HashData(recipientKey, authenticated);
    }
}
