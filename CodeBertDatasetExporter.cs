using System.Globalization;
using System.Text;
using System.Text.Json;

namespace GeminiNuGetAuditor;

public static class CodeBertDatasetExporter
{
    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        WriteIndented = true
    };

    public static CodeBertDatasetExportResult Export(
        string outputDirectory,
        string projectName,
        IReadOnlyCollection<NuGetPackageReference> packageReferences,
        IReadOnlyCollection<GroundTruthLabel> groundTruthLabels)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(outputDirectory);
        ArgumentException.ThrowIfNullOrWhiteSpace(projectName);
        ArgumentNullException.ThrowIfNull(packageReferences);
        ArgumentNullException.ThrowIfNull(groundTruthLabels);

        Directory.CreateDirectory(outputDirectory);

        var labelLookup = groundTruthLabels
            .GroupBy(x => x.PackageName, StringComparer.OrdinalIgnoreCase)
            .ToDictionary(x => x.Key, x => x.First(), StringComparer.OrdinalIgnoreCase);

        var records = new List<CodeBertDatasetRecord>();
        var orderedPackages = packageReferences
            .Where(x => !string.IsNullOrWhiteSpace(x.PackageName))
            .OrderBy(x => StableHash($"{x.PackageName}@{x.CurrentVersion}"))
            .ToList();

        foreach (var package in orderedPackages)
        {
            labelLookup.TryGetValue(package.PackageName, out var label);
            var baseRecord = CreateRecord(package, label, package.PackageName, package.CurrentVersion, "original");
            records.Add(baseRecord);

            records.Add(CreateRecord(
                package,
                label,
                package.PackageName,
                NormalizeVersionForMutation(package.CurrentVersion),
                "semantic_version_normalization"));

            records.Add(CreateRecord(
                package,
                label,
                $"{package.PackageName}.SafeDummy",
                "1.0.0",
                "safe_dummy_dependency",
                forcedLabel: false));
        }

        AssignSplits(records);

        var timestamp = DateTime.UtcNow.ToString("yyyyMMdd-HHmmss", CultureInfo.InvariantCulture);
        var jsonPath = Path.Combine(outputDirectory, $"codebert-dataset-{projectName}-{timestamp}.json");
        var csvPath = Path.Combine(outputDirectory, $"codebert-dataset-{projectName}-{timestamp}.csv");

        File.WriteAllText(jsonPath, JsonSerializer.Serialize(records, JsonOptions), Encoding.UTF8);
        File.WriteAllText(csvPath, ToCsv(records), Encoding.UTF8);

        return new CodeBertDatasetExportResult
        {
            JsonPath = jsonPath,
            CsvPath = csvPath,
            TotalRecords = records.Count,
            TrainingCount = records.Count(x => x.Split == "training"),
            ValidationCount = records.Count(x => x.Split == "validation"),
            TestingCount = records.Count(x => x.Split == "testing")
        };
    }

    private static CodeBertDatasetRecord CreateRecord(
        NuGetPackageReference package,
        GroundTruthLabel? label,
        string mutatedPackageName,
        string mutatedVersion,
        string augmentationType,
        bool? forcedLabel = null)
    {
        var vulnerable = forcedLabel ?? label?.IsVulnerable ?? false;
        var safePackageName = mutatedPackageName ?? string.Empty;
        var safeVersion = string.IsNullOrWhiteSpace(mutatedVersion) ? "Not specified" : mutatedVersion;

        return new CodeBertDatasetRecord
        {
            Id = StableHash($"{safePackageName}@{safeVersion}:{augmentationType}").ToString("X8", CultureInfo.InvariantCulture),
            PackageName = package.PackageName ?? string.Empty,
            CurrentVersion = package.CurrentVersion ?? string.Empty,
            MutatedPackageName = safePackageName,
            MutatedVersion = safeVersion,
            CsprojSnippet = BuildCsprojSnippet(safePackageName, safeVersion, augmentationType),
            Label = vulnerable,
            LabelId = vulnerable ? 1 : 0,
            AugmentationType = augmentationType,
            CVE_ID = forcedLabel == false ? string.Empty : label?.CVE_ID ?? string.Empty,
            Severity = forcedLabel == false ? string.Empty : label?.Severity ?? string.Empty,
            AdvisoryId = forcedLabel == false ? string.Empty : label?.AdvisoryId ?? string.Empty
        };
    }

    private static string BuildCsprojSnippet(string packageName, string version, string augmentationType)
    {
        return augmentationType switch
        {
            "semantic_version_normalization" => $"<ItemGroup><PackageReference Include=\"{EscapeXml(packageName)}\"><Version>{EscapeXml(version)}</Version></PackageReference></ItemGroup>",
            "safe_dummy_dependency" => $"<ItemGroup><PackageReference Include=\"{EscapeXml(packageName)}\" Version=\"{EscapeXml(version)}\" PrivateAssets=\"all\" /></ItemGroup>",
            _ => $"<ItemGroup><PackageReference Include=\"{EscapeXml(packageName)}\" Version=\"{EscapeXml(version)}\" /></ItemGroup>"
        };
    }

    private static string NormalizeVersionForMutation(string version)
    {
        if (string.IsNullOrWhiteSpace(version) || string.Equals(version, "Not specified", StringComparison.OrdinalIgnoreCase))
        {
            return "1.0.0";
        }

        var cleaned = version.Trim();
        return cleaned.StartsWith("[", StringComparison.Ordinal) ||
               cleaned.StartsWith("(", StringComparison.Ordinal) ||
               cleaned.Contains('*')
            ? cleaned
            : $"[{cleaned}]";
    }

    private static void AssignSplits(List<CodeBertDatasetRecord> records)
    {
        if (records.Count == 0)
        {
            return;
        }

        var trainingCount = (int)Math.Round(records.Count * 0.70, MidpointRounding.AwayFromZero);
        var validationCount = (int)Math.Round(records.Count * 0.15, MidpointRounding.AwayFromZero);

        if (records.Count >= 3)
        {
            validationCount = Math.Max(1, validationCount);
            var testingCount = Math.Max(1, records.Count - trainingCount - validationCount);

            while (trainingCount + validationCount + testingCount > records.Count && trainingCount > 1)
            {
                trainingCount--;
            }
        }

        if (trainingCount + validationCount > records.Count)
        {
            validationCount = Math.Max(0, records.Count - trainingCount);
        }

        for (var i = 0; i < records.Count; i++)
        {
            records[i].Split = i < trainingCount
                ? "training"
                : i < trainingCount + validationCount
                    ? "validation"
                    : "testing";
        }
    }

    private static string ToCsv(IEnumerable<CodeBertDatasetRecord> records)
    {
        var builder = new StringBuilder();
        builder.AppendLine("Id,Split,PackageName,CurrentVersion,MutatedPackageName,MutatedVersion,CsprojSnippet,Label,LabelId,AugmentationType,CVE_ID,Severity,AdvisoryId");

        foreach (var record in records)
        {
            builder.AppendLine(string.Join(
                ',',
                EscapeCsv(record.Id),
                EscapeCsv(record.Split),
                EscapeCsv(record.PackageName),
                EscapeCsv(record.CurrentVersion),
                EscapeCsv(record.MutatedPackageName),
                EscapeCsv(record.MutatedVersion),
                EscapeCsv(record.CsprojSnippet),
                record.Label ? "true" : "false",
                record.LabelId.ToString(CultureInfo.InvariantCulture),
                EscapeCsv(record.AugmentationType),
                EscapeCsv(record.CVE_ID),
                EscapeCsv(record.Severity),
                EscapeCsv(record.AdvisoryId)));
        }

        return builder.ToString();
    }

    private static string EscapeCsv(string value)
    {
        var safeValue = value ?? string.Empty;
        return safeValue.Contains(',') || safeValue.Contains('"') || safeValue.Contains('\n') || safeValue.Contains('\r')
            ? $"\"{safeValue.Replace("\"", "\"\"", StringComparison.Ordinal)}\""
            : safeValue;
    }

    private static string EscapeXml(string value)
    {
        return (value ?? string.Empty)
            .Replace("&", "&amp;", StringComparison.Ordinal)
            .Replace("\"", "&quot;", StringComparison.Ordinal)
            .Replace("<", "&lt;", StringComparison.Ordinal)
            .Replace(">", "&gt;", StringComparison.Ordinal);
    }

    private static int StableHash(string value)
    {
        unchecked
        {
            var hash = 17;
            foreach (var character in value ?? string.Empty)
            {
                hash = (hash * 31) + character;
            }

            return hash & int.MaxValue;
        }
    }
}

public sealed class CodeBertDatasetExportResult
{
    public string JsonPath { get; set; } = string.Empty;
    public string CsvPath { get; set; } = string.Empty;
    public int TotalRecords { get; set; }
    public int TrainingCount { get; set; }
    public int ValidationCount { get; set; }
    public int TestingCount { get; set; }
}
