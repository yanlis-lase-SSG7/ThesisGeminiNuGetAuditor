using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace GeminiNuGetAuditor;

public class Program
{
    private const string GeminiApiKeyEnvironmentVariableName = "GEMINI_API_KEY";
    private const string GeminiModelName = "gemini-pro";
    private static readonly JsonSerializerOptions SerializerOptions = new()
    {
        PropertyNameCaseInsensitive = true,
        WriteIndented = true
    };

    public static async Task<int> Main(string[] args)
    {
        try
        {
            var csprojPath = ResolveCsprojPath(args);
            var packageReferences = CsprojPackageExtractor.ExtractPackageReferences(csprojPath);

            if (packageReferences.Count == 0)
            {
                Console.WriteLine("Tidak ada PackageReference yang ditemukan pada file .csproj target.");
                return 0;
            }

            var packageText = BuildPackagePrompt(packageReferences);
            var geminiResponse = await AnalyzeWithGemini(packageText);
            var normalizedResponse = NormalizeResponse(packageReferences, geminiResponse);
            var outputPath = SaveAuditResult(csprojPath, packageReferences, normalizedResponse);
            var vulnerableCount = normalizedResponse.VulnerabilityReports.Count(x => x.IsVulnerable);

            Console.WriteLine($"Audit selesai. {packageReferences.Count} package dianalisis.");
            Console.WriteLine($"Package rentan terdeteksi: {vulnerableCount}.");
            Console.WriteLine($"Hasil tersimpan di: {outputPath}");
            return 0;
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"Audit gagal: {ex.Message}");
            return 1;
        }
    }

    public static Task<GeminiResponse?> AnalyzeWithGemini(string packageText)
    {
        return AnalyzeWithGemini(GetGeminiApiKey(), packageText);
    }

    public static string GetGeminiApiKey()
    {
        var apiKey = Environment.GetEnvironmentVariable(GeminiApiKeyEnvironmentVariableName);

        if (IsUsableApiKey(apiKey))
        {
            return apiKey!;
        }

        foreach (var appSettingsPath in GetAppSettingsPaths())
        {
            if (!File.Exists(appSettingsPath))
            {
                continue;
            }

            using var stream = File.OpenRead(appSettingsPath);
            using var document = JsonDocument.Parse(stream);

            if (!document.RootElement.TryGetProperty("Gemini", out var geminiSection) ||
                geminiSection.ValueKind != JsonValueKind.Object ||
                !geminiSection.TryGetProperty("ApiKey", out var apiKeyProperty))
            {
                continue;
            }

            var appSettingsApiKey = apiKeyProperty.GetString();

            if (IsUsableApiKey(appSettingsApiKey))
            {
                return appSettingsApiKey!;
            }
        }

        throw new InvalidOperationException(
            "Gemini API key tidak ditemukan. Set environment variable 'GEMINI_API_KEY' atau isi 'Gemini:ApiKey' pada appsettings.local.json/appsettings.json dengan nilai valid.");
    }

    public static async Task<GeminiResponse?> AnalyzeWithGemini(string apiKey, string packageText)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(apiKey);
        ArgumentException.ThrowIfNullOrWhiteSpace(packageText);

        using var httpClient = new HttpClient();
        httpClient.DefaultRequestHeaders.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
        httpClient.DefaultRequestHeaders.Add("X-Goog-Api-Key", apiKey);

        var prompt = $$"""
You are a NuGet security auditor.
Return ONLY valid JSON.
Do not return markdown.
Do not return code fences.
Do not return explanations.
Do not return any text before or after the JSON.

The JSON must match this exact C# model structure and property names:
{
  "VulnerabilityReports": [
    {
      "PackageName": "string",
      "CurrentVersion": "string",
      "IsVulnerable": true,
      "CVE_ID": "string",
      "Severity": "string",
      "MitigationPlan": "string"
    }
  ]
}

Rules:
- Always return a single JSON object.
- Always include the `VulnerabilityReports` array.
- Return one item per package.
- Use empty string for unknown string values.
- Use false for `IsVulnerable` when no known vulnerability is identified.

Analyze these NuGet packages:
{{packageText}}
""";

        var requestBody = new
        {
            contents = new[]
            {
                new
                {
                    parts = new[]
                    {
                        new { text = prompt }
                    }
                }
            },
            generationConfig = new
            {
                responseMimeType = "application/json"
            }
        };

        using var content = new StringContent(JsonSerializer.Serialize(requestBody), Encoding.UTF8, "application/json");
        using var response = await httpClient.PostAsync($"https://generativelanguage.googleapis.com/v1beta/models/{GeminiModelName}:generateContent", content);
        response.EnsureSuccessStatusCode();

        var responseContent = await response.Content.ReadAsStringAsync();
        var geminiApiResponse = JsonSerializer.Deserialize<GeminiApiResponse>(responseContent, SerializerOptions);
        var json = geminiApiResponse?.Candidates?.FirstOrDefault()?.Content?.Parts?.FirstOrDefault()?.Text;

        if (string.IsNullOrWhiteSpace(json))
        {
            return null;
        }

        return JsonSerializer.Deserialize<GeminiResponse>(ExtractJsonPayload(json), SerializerOptions);
    }

    private static IEnumerable<string> GetAppSettingsPaths()
    {
        var baseLocalPath = Path.Combine(AppContext.BaseDirectory, "appsettings.local.json");
        yield return baseLocalPath;

        var baseDirectoryPath = Path.Combine(AppContext.BaseDirectory, "appsettings.json");
        yield return baseDirectoryPath;

        var currentLocalPath = Path.Combine(Directory.GetCurrentDirectory(), "appsettings.local.json");

        if (!string.Equals(baseLocalPath, currentLocalPath, StringComparison.OrdinalIgnoreCase))
        {
            yield return currentLocalPath;
        }

        var currentDirectoryPath = Path.Combine(Directory.GetCurrentDirectory(), "appsettings.json");

        if (!string.Equals(baseDirectoryPath, currentDirectoryPath, StringComparison.OrdinalIgnoreCase))
        {
            yield return currentDirectoryPath;
        }
    }

    private static string ResolveCsprojPath(string[] args)
    {
        var providedPath = args.FirstOrDefault(x => x.EndsWith(".csproj", StringComparison.OrdinalIgnoreCase));

        if (string.IsNullOrWhiteSpace(providedPath))
        {
            Console.Write("Masukkan path file .csproj yang akan diaudit: ");
            providedPath = Console.ReadLine();
        }

        if (string.IsNullOrWhiteSpace(providedPath))
        {
            throw new InvalidOperationException("Path file .csproj wajib diisi.");
        }

        var fullPath = Path.GetFullPath(providedPath);

        if (!File.Exists(fullPath))
        {
            throw new FileNotFoundException("File .csproj tidak ditemukan.", fullPath);
        }

        return fullPath;
    }

    private static string BuildPackagePrompt(IEnumerable<NuGetPackageReference> packageReferences)
    {
        var builder = new StringBuilder();

        foreach (var packageReference in packageReferences)
        {
            builder.AppendLine($"- {packageReference.PackageName}: {packageReference.CurrentVersion}");
        }

        return builder.ToString().TrimEnd();
    }

    private static GeminiResponse NormalizeResponse(
        IReadOnlyCollection<NuGetPackageReference> packageReferences,
        GeminiResponse? geminiResponse)
    {
        var reportLookup = (geminiResponse?.VulnerabilityReports ?? new List<VulnerabilityReport>())
            .Where(x => !string.IsNullOrWhiteSpace(x.PackageName))
            .GroupBy(x => x.PackageName, StringComparer.OrdinalIgnoreCase)
            .ToDictionary(x => x.Key, x => x.First(), StringComparer.OrdinalIgnoreCase);

        var normalizedReports = packageReferences
            .Select(packageReference =>
            {
                if (reportLookup.TryGetValue(packageReference.PackageName, out var report))
                {
                    report.PackageName = packageReference.PackageName;
                    report.CurrentVersion = packageReference.CurrentVersion;
                    report.CVE_ID ??= string.Empty;
                    report.Severity ??= string.Empty;
                    report.MitigationPlan ??= string.Empty;
                    return report;
                }

                return new VulnerabilityReport
                {
                    PackageName = packageReference.PackageName,
                    CurrentVersion = packageReference.CurrentVersion,
                    IsVulnerable = false,
                    CVE_ID = string.Empty,
                    Severity = string.Empty,
                    MitigationPlan = string.Empty
                };
            })
            .ToList();

        return new GeminiResponse
        {
            VulnerabilityReports = normalizedReports
        };
    }

    private static string SaveAuditResult(
        string csprojPath,
        IReadOnlyCollection<NuGetPackageReference> packageReferences,
        GeminiResponse geminiResponse)
    {
        var outputDirectory = Path.Combine(AppContext.BaseDirectory, "audit-results");
        Directory.CreateDirectory(outputDirectory);

        var outputFilePath = Path.Combine(
            outputDirectory,
            $"audit-{Path.GetFileNameWithoutExtension(csprojPath)}-{DateTime.UtcNow:yyyyMMdd-HHmmss}.json");

        var sessionRecord = new AuditSessionRecord
        {
            GeneratedAtUtc = DateTimeOffset.UtcNow,
            SourceProjectPath = csprojPath,
            ModelName = GeminiModelName,
            ExtractedPackages = packageReferences.ToList(),
            VulnerabilityReports = geminiResponse.VulnerabilityReports
        };

        File.WriteAllText(outputFilePath, JsonSerializer.Serialize(sessionRecord, SerializerOptions));
        return outputFilePath;
    }

    private static bool IsUsableApiKey(string? apiKey)
    {
        return !string.IsNullOrWhiteSpace(apiKey) &&
               !string.Equals(apiKey, "REPLACE_WITH_YOUR_NEW_GEMINI_API_KEY", StringComparison.OrdinalIgnoreCase);
    }

    private static string ExtractJsonPayload(string responseText)
    {
        var trimmedResponse = responseText.Trim();

        if (trimmedResponse.StartsWith("```", StringComparison.Ordinal))
        {
            var newlineIndex = trimmedResponse.IndexOf('\n');

            if (newlineIndex >= 0)
            {
                trimmedResponse = trimmedResponse[(newlineIndex + 1)..];
            }

            var closingFenceIndex = trimmedResponse.LastIndexOf("```", StringComparison.Ordinal);

            if (closingFenceIndex >= 0)
            {
                trimmedResponse = trimmedResponse[..closingFenceIndex];
            }
        }

        var jsonStartIndex = trimmedResponse.IndexOf('{');
        var jsonEndIndex = trimmedResponse.LastIndexOf('}');

        if (jsonStartIndex >= 0 && jsonEndIndex >= jsonStartIndex)
        {
            return trimmedResponse.Substring(jsonStartIndex, jsonEndIndex - jsonStartIndex + 1);
        }

        return trimmedResponse;
    }

    private sealed class GeminiApiResponse
    {
        [JsonPropertyName("candidates")]
        public List<GeminiCandidate>? Candidates { get; set; }
    }

    private sealed class GeminiCandidate
    {
        [JsonPropertyName("content")]
        public GeminiContent? Content { get; set; }
    }

    private sealed class GeminiContent
    {
        [JsonPropertyName("parts")]
        public List<GeminiPart>? Parts { get; set; }
    }

    private sealed class GeminiPart
    {
        [JsonPropertyName("text")]
        public string? Text { get; set; }
    }
}
