using System.Reflection;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace Deep.Protocol.GoldenVectors;

public sealed record GoldenVectorSet
{
    public string Name { get; init; } = string.Empty;
    public string SourceRepository { get; init; } = string.Empty;
    public string SourceCommit { get; init; } = string.Empty;
    public IReadOnlyList<GoldenVector> Vectors { get; init; } = Array.Empty<GoldenVector>();
}

public sealed record GoldenVector
{
    public string Id { get; init; } = string.Empty;
    public string Kind { get; init; } = string.Empty;
    public string? Message { get; init; }
    public string? Body { get; init; }
    public ulong? TimestampMs { get; init; }
    public string? PlaintextHex { get; init; }
    public string? PaddedHex { get; init; }
    public string? Hex { get; init; }
    public string? SeedHex { get; init; }
    public string? Ed25519PublicKeyHex { get; init; }
    public string? X25519PublicKeyHex { get; init; }
    public int? MutationOffset { get; init; }
    public string? ExpectedError { get; init; }
}

public static class GoldenVectorLoader
{
    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        PropertyNameCaseInsensitive = true,
        ReadCommentHandling = JsonCommentHandling.Skip,
        AllowTrailingCommas = true,
        Converters = { new JsonStringEnumConverter() }
    };

    public static GoldenVectorSet Load(string resourceName)
    {
        var assembly = typeof(GoldenVectorLoader).Assembly;
        var fullName = assembly
            .GetManifestResourceNames()
            .SingleOrDefault(name => name.EndsWith(resourceName, StringComparison.Ordinal));

        if (fullName is null)
        {
            throw new InvalidOperationException($"Golden vector resource '{resourceName}' was not found.");
        }

        using var stream = assembly.GetManifestResourceStream(fullName)
            ?? throw new InvalidOperationException($"Golden vector resource '{resourceName}' could not be opened.");
        return JsonSerializer.Deserialize<GoldenVectorSet>(stream, JsonOptions)
            ?? throw new InvalidOperationException($"Golden vector resource '{resourceName}' was empty.");
    }

    public static GoldenVector GetRequired(this GoldenVectorSet set, string id) =>
        set.Vectors.Single(vector => StringComparer.Ordinal.Equals(vector.Id, id));
}
