namespace Deep.Protocol.Tests;

internal static class VectorDiffs
{
    public static void AssertHex(string id, string? expected, string actual)
    {
        if (StringComparer.OrdinalIgnoreCase.Equals(expected, actual))
        {
            return;
        }

        var directory = Path.Combine(AppContext.BaseDirectory, "..", "..", "..", "..", "..", "artifacts", "vector-diffs");
        Directory.CreateDirectory(directory);
        var path = Path.Combine(directory, Sanitize(id) + ".diff.txt");
        File.WriteAllText(
            path,
            $"vector: {id}{Environment.NewLine}expected: {expected}{Environment.NewLine}actual:   {actual}{Environment.NewLine}");
        Assert.Equal(expected, actual);
    }

    private static string Sanitize(string value)
    {
        foreach (var invalid in Path.GetInvalidFileNameChars())
        {
            value = value.Replace(invalid, '_');
        }

        return value.Replace('/', '_');
    }
}
