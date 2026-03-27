using System.Text.Json;

namespace GeminiNuGetAuditor;

public static class SecurityReferenceProvider
{
    private const string AdvisoryDbFileName = "github-advisory-db.json";

    public static string GetSecurityContext(List<string> packages)
    {
        if (packages is null || packages.Count == 0)
        {
            return "[]";
        }

        var advisoryDbPath = Path.Combine(AppContext.BaseDirectory, AdvisoryDbFileName);

        if (!File.Exists(advisoryDbPath))
        {
            advisoryDbPath = Path.Combine(Directory.GetCurrentDirectory(), AdvisoryDbFileName);
        }

        if (!File.Exists(advisoryDbPath))
        {
            return "[]";
        }

        using var stream = File.OpenRead(advisoryDbPath);
        using var document = JsonDocument.Parse(stream);

        var packageSet = new HashSet<string>(
            packages.Where(x => !string.IsNullOrWhiteSpace(x)).Select(x => x.Trim()),
            StringComparer.OrdinalIgnoreCase);

        var advisories = GetAdvisoryArray(document.RootElement);
        var matched = new List<JsonElement>();

        foreach (var advisory in advisories)
        {
            var packageName = TryGetPackageName(advisory);

            if (!string.IsNullOrWhiteSpace(packageName) && packageSet.Contains(packageName))
            {
                matched.Add(advisory);
            }
        }

        return JsonSerializer.Serialize(matched, new JsonSerializerOptions { WriteIndented = true });
    }

    private static IEnumerable<JsonElement> GetAdvisoryArray(JsonElement root)
    {
        if (root.ValueKind == JsonValueKind.Array)
        {
            foreach (var item in root.EnumerateArray())
            {
                yield return item;
            }

            yield break;
        }

        if (root.ValueKind == JsonValueKind.Object)
        {
            if (root.TryGetProperty("advisories", out var advisories) && advisories.ValueKind == JsonValueKind.Array)
            {
                foreach (var item in advisories.EnumerateArray())
                {
                    yield return item;
                }

                yield break;
            }

            if (root.TryGetProperty("vulnerabilities", out var vulnerabilities) && vulnerabilities.ValueKind == JsonValueKind.Array)
            {
                foreach (var item in vulnerabilities.EnumerateArray())
                {
                    yield return item;
                }
            }
        }
    }

    private static string TryGetPackageName(JsonElement advisory)
    {
        if (advisory.ValueKind != JsonValueKind.Object)
        {
            return string.Empty;
        }

        if (advisory.TryGetProperty("PackageName", out var packageName) && packageName.ValueKind == JsonValueKind.String)
        {
            return packageName.GetString() ?? string.Empty;
        }

        if (advisory.TryGetProperty("packageName", out var camelCasePackageName) && camelCasePackageName.ValueKind == JsonValueKind.String)
        {
            return camelCasePackageName.GetString() ?? string.Empty;
        }

        if (advisory.TryGetProperty("package", out var package))
        {
            if (package.ValueKind == JsonValueKind.String)
            {
                return package.GetString() ?? string.Empty;
            }

            if (package.ValueKind == JsonValueKind.Object)
            {
                if (package.TryGetProperty("name", out var nestedName) && nestedName.ValueKind == JsonValueKind.String)
                {
                    return nestedName.GetString() ?? string.Empty;
                }

                if (package.TryGetProperty("Name", out var nestedPascalName) && nestedPascalName.ValueKind == JsonValueKind.String)
                {
                    return nestedPascalName.GetString() ?? string.Empty;
                }
            }
        }

        if (advisory.TryGetProperty("name", out var name) && name.ValueKind == JsonValueKind.String)
        {
            return name.GetString() ?? string.Empty;
        }

        return string.Empty;
    }
}
