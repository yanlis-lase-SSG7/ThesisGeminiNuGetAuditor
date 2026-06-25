using System.Text.Json;

namespace GeminiNuGetAuditor;

public static class GroundTruthProvider
{
    private static readonly JsonDocumentOptions JsonOptions = new()
    {
        CommentHandling = JsonCommentHandling.Skip,
        AllowTrailingCommas = true
    };

    public static IReadOnlyList<GroundTruthLabel> BuildLabels(
        IReadOnlyCollection<NuGetPackageReference> packageReferences,
        string securityContext)
    {
        ArgumentNullException.ThrowIfNull(packageReferences);

        var advisoryLookup = ParseSecurityContext(securityContext)
            .GroupBy(x => x.PackageName, StringComparer.OrdinalIgnoreCase)
            .ToDictionary(x => x.Key, x => x.First(), StringComparer.OrdinalIgnoreCase);

        return packageReferences.Select(package =>
        {
            var packageName = package.PackageName ?? string.Empty;
            advisoryLookup.TryGetValue(packageName, out var advisory);

            return new GroundTruthLabel
            {
                PackageName = packageName,
                CurrentVersion = package.CurrentVersion ?? string.Empty,
                IsVulnerable = advisory is not null,
                CVE_ID = advisory?.CVE_ID ?? string.Empty,
                Severity = advisory?.Severity ?? string.Empty,
                AdvisoryId = advisory?.AdvisoryId ?? string.Empty,
                VulnerableVersionRange = advisory?.VulnerableVersionRange ?? string.Empty,
                FirstPatchedVersion = advisory?.FirstPatchedVersion ?? string.Empty,
                ReferenceUrl = advisory?.ReferenceUrl ?? string.Empty
            };
        }).ToList();
    }

    public static HashSet<string> ExtractVulnerablePackageNames(string securityContext)
    {
        return ParseSecurityContext(securityContext)
            .Select(x => x.PackageName)
            .Where(x => !string.IsNullOrWhiteSpace(x))
            .ToHashSet(StringComparer.OrdinalIgnoreCase);
    }

    private static IReadOnlyList<SecurityAdvisoryLabel> ParseSecurityContext(string securityContext)
    {
        if (string.IsNullOrWhiteSpace(securityContext))
        {
            return Array.Empty<SecurityAdvisoryLabel>();
        }

        try
        {
            using var document = JsonDocument.Parse(securityContext, JsonOptions);
            return GetAdvisories(document.RootElement)
                .Select(ToSecurityAdvisoryLabel)
                .Where(x => !string.IsNullOrWhiteSpace(x.PackageName))
                .ToList();
        }
        catch (JsonException)
        {
            return Array.Empty<SecurityAdvisoryLabel>();
        }
    }

    private static IEnumerable<JsonElement> GetAdvisories(JsonElement root)
    {
        if (root.ValueKind == JsonValueKind.Array)
        {
            foreach (var item in root.EnumerateArray())
            {
                yield return item;
            }

            yield break;
        }

        if (root.ValueKind != JsonValueKind.Object)
        {
            yield break;
        }

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

    private static SecurityAdvisoryLabel ToSecurityAdvisoryLabel(JsonElement advisory)
    {
        if (advisory.ValueKind != JsonValueKind.Object)
        {
            return new SecurityAdvisoryLabel();
        }

        return new SecurityAdvisoryLabel
        {
            PackageName = ReadPackageName(advisory),
            CVE_ID = ReadString(advisory, "CVE", "cve", "CVE_ID", "cveId"),
            Severity = ReadString(advisory, "Severity", "severity"),
            AdvisoryId = ReadString(advisory, "GHSA", "ghsa", "GHSA_ID", "ghsaId", "AdvisoryId", "advisoryId"),
            VulnerableVersionRange = ReadString(advisory, "VulnerableVersionRange", "vulnerableVersionRange"),
            FirstPatchedVersion = ReadFirstPatchedVersion(advisory),
            ReferenceUrl = ReadString(advisory, "ReferenceUrl", "referenceUrl", "permalink", "url")
        };
    }

    private static string ReadPackageName(JsonElement advisory)
    {
        var direct = ReadString(advisory, "PackageName", "packageName", "name");
        if (!string.IsNullOrWhiteSpace(direct))
        {
            return direct;
        }

        if (!advisory.TryGetProperty("package", out var package))
        {
            return string.Empty;
        }

        if (package.ValueKind == JsonValueKind.String)
        {
            return package.GetString() ?? string.Empty;
        }

        if (package.ValueKind == JsonValueKind.Object)
        {
            return ReadString(package, "name", "Name");
        }

        return string.Empty;
    }

    private static string ReadFirstPatchedVersion(JsonElement advisory)
    {
        var direct = ReadString(advisory, "FirstPatchedVersion", "firstPatchedVersion");
        if (!string.IsNullOrWhiteSpace(direct))
        {
            return direct;
        }

        if (advisory.TryGetProperty("firstPatchedVersion", out var patched) &&
            patched.ValueKind == JsonValueKind.Object)
        {
            return ReadString(patched, "identifier", "Identifier");
        }

        return string.Empty;
    }

    private static string ReadString(JsonElement element, params string[] propertyNames)
    {
        foreach (var propertyName in propertyNames)
        {
            if (element.TryGetProperty(propertyName, out var property) &&
                property.ValueKind == JsonValueKind.String)
            {
                return property.GetString() ?? string.Empty;
            }
        }

        return string.Empty;
    }

    private sealed class SecurityAdvisoryLabel
    {
        public string PackageName { get; set; } = string.Empty;
        public string CVE_ID { get; set; } = string.Empty;
        public string Severity { get; set; } = string.Empty;
        public string AdvisoryId { get; set; } = string.Empty;
        public string VulnerableVersionRange { get; set; } = string.Empty;
        public string FirstPatchedVersion { get; set; } = string.Empty;
        public string ReferenceUrl { get; set; } = string.Empty;
    }
}
