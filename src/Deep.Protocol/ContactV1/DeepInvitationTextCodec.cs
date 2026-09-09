namespace Deep.Protocol.ContactV1;

/// <summary>
/// Canonical human/deep-link projection of one exact DIA1 record.
/// </summary>
public static class DeepInvitationTextCodec
{
    public const string Prefix = "deepinvite:";
    public const int ExactRecordSize = 225;
    public const int ExactPayloadTextLength = 300;
    public const int ExactTextLength = 311;

    public static ContactRecord DecodeCanonical(string text)
    {
        ArgumentNullException.ThrowIfNull(text);
        if (text.Length != ExactTextLength
            || !text.StartsWith(Prefix, StringComparison.Ordinal))
        {
            throw Invalid("InvitationTextNonCanonical");
        }

        var payload = text.AsSpan(Prefix.Length);
        Span<char> base64 = stackalloc char[ExactPayloadTextLength];
        for (var index = 0; index < payload.Length; index++)
        {
            var character = payload[index];
            if (!IsBase64Url(character))
            {
                throw Invalid("InvitationTextNonCanonical");
            }

            base64[index] = character switch
            {
                '-' => '+',
                '_' => '/',
                _ => character,
            };
        }

        Span<byte> canonical = stackalloc byte[ExactRecordSize];
        if (!Convert.TryFromBase64Chars(base64, canonical, out var bytesWritten)
            || bytesWritten != ExactRecordSize)
        {
            throw Invalid("InvitationTextInvalidBase64Url");
        }

        var record = ContactCodec.Decode(ProtocolMagic.DIA1, canonical);
        if (!string.Equals(text, EncodeCanonical(record), StringComparison.Ordinal))
        {
            throw Invalid("InvitationTextNonCanonical");
        }

        return record;
    }

    public static string EncodeCanonical(ContactRecord invitation)
    {
        ArgumentNullException.ThrowIfNull(invitation);
        if (!string.Equals(invitation.Magic, ProtocolMagic.DIA1, StringComparison.Ordinal)
            || invitation.CanonicalBytes.Length != ExactRecordSize)
        {
            throw new ArgumentException("An exact canonical DIA1 record is required.", nameof(invitation));
        }

        var payload = Convert.ToBase64String(invitation.CanonicalBytes.Span)
            .TrimEnd('=')
            .Replace('+', '-')
            .Replace('/', '_');
        if (payload.Length != ExactPayloadTextLength)
        {
            throw new InvalidOperationException("The frozen DIA1 text size is inconsistent.");
        }

        return Prefix + payload;
    }

    private static bool IsBase64Url(char character) =>
        character is >= 'A' and <= 'Z'
        or >= 'a' and <= 'z'
        or >= '0' and <= '9'
        or '-' or '_';

    private static ContactFormatException Invalid(string code) =>
        new(ContactValidationStage.Header, code);
}
