using System.Text;
using System.Text.Json;

namespace Deep.Protocol.DeepExtension.ManagedIngress;

public static class ManagedIngressCapabilityDocumentCodec
{
    private static readonly string[] RequiredProperties =
    [
        "schemaVersion",
        "contractId",
        "minimumVersion",
        "maximumVersion",
        "requestMediaType",
        "responseMediaType",
        "errorMediaType",
        "minimumFrameBytes",
        "maximumFrameBytes",
        "maximumHeaderListBytes",
        "maximumHeaderFields",
        "ready",
        "retryAfterSeconds",
        "httpVersions",
        "criticalFeatures",
        "optionalFeatures"
    ];

    public static byte[] Encode(ManagedIngressCapabilityDocument document)
    {
        ArgumentNullException.ThrowIfNull(document);
        ValidatePolicy(document);

        using var stream = new MemoryStream();
        using (var writer = new Utf8JsonWriter(stream, new JsonWriterOptions
        {
            Indented = false,
            SkipValidation = false
        }))
        {
            writer.WriteStartObject();
            writer.WriteNumber("schemaVersion", document.SchemaVersion);
            writer.WriteString("contractId", document.ContractId);
            writer.WriteNumber("minimumVersion", document.MinimumVersion);
            writer.WriteNumber("maximumVersion", document.MaximumVersion);
            writer.WriteString("requestMediaType", document.RequestMediaType);
            writer.WriteString("responseMediaType", document.ResponseMediaType);
            writer.WriteString("errorMediaType", document.ErrorMediaType);
            writer.WriteNumber("minimumFrameBytes", document.MinimumFrameBytes);
            writer.WriteNumber("maximumFrameBytes", document.MaximumFrameBytes);
            writer.WriteNumber("maximumHeaderListBytes", document.MaximumHeaderListBytes);
            writer.WriteNumber("maximumHeaderFields", document.MaximumHeaderFields);
            writer.WriteBoolean("ready", document.Ready);
            writer.WriteNumber("retryAfterSeconds", document.RetryAfterSeconds);
            WriteStrings(writer, "httpVersions", document.HttpVersions);
            WriteStrings(writer, "criticalFeatures", document.CriticalFeatures);
            WriteStrings(writer, "optionalFeatures", document.OptionalFeatures);
            writer.WriteEndObject();
        }

        var encoded = stream.ToArray();
        if (encoded.Length > ManagedIngressLimits.MaximumCapabilityDocumentBytes)
        {
            throw Error(
                ManagedIngressContractError.CapabilityDocumentOutOfRange,
                "The capability document exceeds its hard bound.");
        }

        return encoded;
    }

    public static ManagedIngressCapabilityDocument Decode(
        ReadOnlySpan<byte> encoded,
        IReadOnlySet<string> supportedCriticalFeatures)
    {
        ArgumentNullException.ThrowIfNull(supportedCriticalFeatures);
        if (encoded.IsEmpty || encoded.Length > ManagedIngressLimits.MaximumCapabilityDocumentBytes)
        {
            throw Error(
                ManagedIngressContractError.CapabilityDocumentOutOfRange,
                "The capability document length is outside strict bounds.");
        }

        JsonDocument json;
        try
        {
            json = JsonDocument.Parse(encoded.ToArray(), new JsonDocumentOptions
            {
                AllowTrailingCommas = false,
                CommentHandling = JsonCommentHandling.Disallow,
                MaxDepth = 8
            });
        }
        catch (JsonException)
        {
            throw Error(
                ManagedIngressContractError.MalformedCapabilityDocument,
                "The capability document is malformed.");
        }

        using (json)
        {
            if (json.RootElement.ValueKind != JsonValueKind.Object)
            {
                throw Error(
                    ManagedIngressContractError.MalformedCapabilityDocument,
                    "The capability document root must be an object.");
            }

            var seen = new HashSet<string>(StringComparer.Ordinal);
            foreach (var property in json.RootElement.EnumerateObject())
            {
                if (!seen.Add(property.Name) ||
                    !RequiredProperties.Contains(property.Name, StringComparer.Ordinal))
                {
                    throw Error(
                        ManagedIngressContractError.MalformedCapabilityDocument,
                        "The capability document contains duplicate or unknown fields.");
                }
            }

            if (seen.Count != RequiredProperties.Length)
            {
                throw Error(
                    ManagedIngressContractError.MalformedCapabilityDocument,
                    "The capability document is incomplete.");
            }

            try
            {
                var document = new ManagedIngressCapabilityDocument
                {
                    SchemaVersion = RequiredInt(json.RootElement, "schemaVersion"),
                    ContractId = RequiredString(json.RootElement, "contractId"),
                    MinimumVersion = RequiredInt(json.RootElement, "minimumVersion"),
                    MaximumVersion = RequiredInt(json.RootElement, "maximumVersion"),
                    RequestMediaType = RequiredString(json.RootElement, "requestMediaType"),
                    ResponseMediaType = RequiredString(json.RootElement, "responseMediaType"),
                    ErrorMediaType = RequiredString(json.RootElement, "errorMediaType"),
                    MinimumFrameBytes = RequiredInt(json.RootElement, "minimumFrameBytes"),
                    MaximumFrameBytes = RequiredInt(json.RootElement, "maximumFrameBytes"),
                    MaximumHeaderListBytes =
                        RequiredInt(json.RootElement, "maximumHeaderListBytes"),
                    MaximumHeaderFields = RequiredInt(json.RootElement, "maximumHeaderFields"),
                    Ready = RequiredBool(json.RootElement, "ready"),
                    RetryAfterSeconds = RequiredInt(json.RootElement, "retryAfterSeconds"),
                    HttpVersions = RequiredStrings(json.RootElement, "httpVersions"),
                    CriticalFeatures = RequiredStrings(json.RootElement, "criticalFeatures"),
                    OptionalFeatures = RequiredStrings(json.RootElement, "optionalFeatures")
                };
                ValidatePolicy(document);
                if (document.CriticalFeatures.Any(feature =>
                        !supportedCriticalFeatures.Contains(feature)))
                {
                    throw Error(
                        ManagedIngressContractError.UnknownCriticalFeature,
                        "The capability document contains an unknown critical feature.");
                }

                return document;
            }
            catch (InvalidOperationException)
            {
                throw Error(
                    ManagedIngressContractError.MalformedCapabilityDocument,
                    "A capability document field has the wrong JSON type.");
            }
            catch (FormatException)
            {
                throw Error(
                    ManagedIngressContractError.MalformedCapabilityDocument,
                    "A capability document field is invalid.");
            }
            catch (OverflowException)
            {
                throw Error(
                    ManagedIngressContractError.MalformedCapabilityDocument,
                    "A capability document number is outside bounds.");
            }
        }
    }

    private static void ValidatePolicy(ManagedIngressCapabilityDocument document)
    {
        if (document.SchemaVersion != 1 ||
            !StringComparer.Ordinal.Equals(document.ContractId, ManagedIngressH2Contract.ContractId) ||
            document.MinimumVersion != 1 ||
            document.MaximumVersion != 1 ||
            !StringComparer.Ordinal.Equals(
                document.RequestMediaType,
                ManagedIngressH2Contract.OpaqueMediaType) ||
            !StringComparer.Ordinal.Equals(
                document.ResponseMediaType,
                ManagedIngressH2Contract.OpaqueMediaType) ||
            !StringComparer.Ordinal.Equals(
                document.ErrorMediaType,
                ManagedIngressH2Contract.ErrorMediaType) ||
            document.MinimumFrameBytes != ManagedIngressLimits.MinimumOpaqueFrameBytes ||
            document.MaximumFrameBytes != ManagedIngressLimits.MaximumOpaqueFrameBytes ||
            document.MaximumHeaderListBytes !=
                ManagedIngressLimits.MaximumDecodedHeaderListBytes ||
            document.MaximumHeaderFields != ManagedIngressLimits.MaximumHeaderFields ||
            document.HttpVersions is null ||
            document.CriticalFeatures is null ||
            document.OptionalFeatures is null ||
            document.HttpVersions.Count != 1 ||
            !StringComparer.Ordinal.Equals(document.HttpVersions[0], "2") ||
            document.CriticalFeatures.Count is < 1 or > 16 ||
            document.OptionalFeatures.Count > 16 ||
            document.CriticalFeatures.Distinct(StringComparer.Ordinal).Count() !=
                document.CriticalFeatures.Count ||
            document.OptionalFeatures.Distinct(StringComparer.Ordinal).Count() !=
                document.OptionalFeatures.Count ||
            document.CriticalFeatures.Any(feature => !ValidFeature(feature)) ||
            document.OptionalFeatures.Any(feature => !ValidFeature(feature)) ||
            !document.CriticalFeatures.Contains(
                ManagedIngressCapabilityFeatures.OpaqueFrameV1,
                StringComparer.Ordinal) ||
            (document.Ready && document.RetryAfterSeconds != 0) ||
            (!document.Ready &&
             document.RetryAfterSeconds is
                < ManagedIngressLimits.MinimumRetryAfterSeconds or
                > ManagedIngressLimits.MaximumRetryAfterSeconds))
        {
            throw Error(
                ManagedIngressContractError.CapabilityPolicyMismatch,
                "The capability document violates the V1 policy.");
        }
    }

    private static bool ValidFeature(string feature) =>
        feature is not null &&
        feature.Length is >= 1 and <= 64 &&
        feature.All(character =>
            char.IsAsciiLetterOrDigit(character) || character is '-' or '.');

    private static void WriteStrings(
        Utf8JsonWriter writer,
        string propertyName,
        IReadOnlyList<string> values)
    {
        writer.WriteStartArray(propertyName);
        foreach (var value in values)
        {
            writer.WriteStringValue(value);
        }

        writer.WriteEndArray();
    }

    private static int RequiredInt(JsonElement root, string name) =>
        root.GetProperty(name).GetInt32();

    private static bool RequiredBool(JsonElement root, string name)
    {
        var property = root.GetProperty(name);
        if (property.ValueKind is not (JsonValueKind.True or JsonValueKind.False))
        {
            throw new InvalidOperationException();
        }

        return property.GetBoolean();
    }

    private static string RequiredString(JsonElement root, string name)
    {
        var value = root.GetProperty(name).GetString();
        return value ?? throw new InvalidOperationException();
    }

    private static IReadOnlyList<string> RequiredStrings(JsonElement root, string name)
    {
        var property = root.GetProperty(name);
        if (property.ValueKind != JsonValueKind.Array)
        {
            throw new InvalidOperationException();
        }

        var values = new List<string>();
        foreach (var item in property.EnumerateArray())
        {
            values.Add(item.GetString() ?? throw new InvalidOperationException());
            if (values.Count > 16)
            {
                throw new InvalidOperationException();
            }
        }

        return values;
    }

    private static ManagedIngressContractException Error(
        ManagedIngressContractError error,
        string message) => new(error, message);
}
