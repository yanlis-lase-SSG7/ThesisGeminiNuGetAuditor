using System.Diagnostics;
using System.Net;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace GeminiNuGetAuditor;

public class Program
{
    private const string GeminiApiKeyEnvironmentVariableName = "GEMINI_API_KEY";
    private const string GeminiModelEnvironmentVariableName = "GEMINI_MODEL";
    private const string DefaultGeminiModelName = "gemini-flash-latest";
    private static readonly TimeSpan GeminiRequestTimeout = TimeSpan.FromSeconds(60);
    private static readonly JsonSerializerOptions SerializerOptions = new()
    {
        PropertyNameCaseInsensitive = true,
        WriteIndented = true
    };

    public static async Task<int> Main(string[] args)
    {
        var totalStopwatch = Stopwatch.StartNew();

        try
        {
            var csprojPath = ResolveCsprojPath(args);
            var modelName = GetGeminiModelName();
            Console.WriteLine($"Target project: {csprojPath}");
            Console.WriteLine($"Using Gemini model: {modelName}");
            Console.WriteLine("Extracting NuGet packages...");

            var extractionStopwatch = Stopwatch.StartNew();
            var packageReferences = CsprojPackageExtractor.ExtractPackageReferences(csprojPath);
            extractionStopwatch.Stop();

            Console.WriteLine($"Extraction completed in {FormatElapsed(extractionStopwatch.Elapsed)}.");

            if (packageReferences.Count == 0)
            {
                Console.WriteLine("No PackageReference entries were found in the target .csproj file.");
                Console.WriteLine("Gemini request was skipped because there are no NuGet packages to analyze.");
                return 0;
            }

            Console.WriteLine($"Found {packageReferences.Count} package(s) to analyze.");
            Console.WriteLine("Retrieving security reference context from local advisory database...");
            var securityContext = SecurityReferenceProvider.GetSecurityContext(packageReferences.Select(x => x.PackageName).ToList());
            Console.WriteLine("Sending package list to Gemini for security analysis...");

            var analysisStopwatch = Stopwatch.StartNew();
            var geminiResponse = await AnalyzeWithGemini(GetGeminiApiKey(), modelName, packageReferences, securityContext);
            analysisStopwatch.Stop();

            Console.WriteLine($"Gemini analysis completed in {FormatElapsed(analysisStopwatch.Elapsed)}.");
            Console.WriteLine("Gemini response received. Normalizing audit results...");

            var postProcessingStopwatch = Stopwatch.StartNew();
            var normalizedResponse = NormalizeResponse(packageReferences, geminiResponse);
            Console.WriteLine("Saving audit dataset to local JSON file...");
            var outputPath = SaveAuditResult(csprojPath, modelName, packageReferences, normalizedResponse);
            var metricsCsvPath = SaveScanMetricsCsv(csprojPath, normalizedResponse, securityContext);
            postProcessingStopwatch.Stop();

            var vulnerableCount = normalizedResponse.VulnerabilityReports.Count(x => x.IsVulnerable);
            totalStopwatch.Stop();

            Console.WriteLine($"Audit completed. {packageReferences.Count} package(s) were analyzed.");
            Console.WriteLine($"Potentially vulnerable packages detected: {vulnerableCount}.");
            Console.WriteLine($"Post-processing completed in {FormatElapsed(postProcessingStopwatch.Elapsed)}.");
            Console.WriteLine($"Total execution time: {FormatElapsed(totalStopwatch.Elapsed)}.");
            Console.WriteLine($"Audit result saved to: {outputPath}");
            Console.WriteLine($"Metrics CSV saved to: {metricsCsvPath}");
            return 0;
        }
        catch (GeminiConfigurationException ex)
        {
            Console.Error.WriteLine($"Gemini configuration error: {ex.Message}");
            return 1;
        }
        catch (TimeoutException ex)
        {
            Console.Error.WriteLine($"Gemini request timeout: {ex.Message}");
            return 1;
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"Audit failed: {ex.Message}");
            return 1;
        }
    }

    public static Task<GeminiResponse?> AnalyzeWithGemini(IReadOnlyCollection<NuGetPackageReference> packageReferences, string securityContext)
    {
        return AnalyzeWithGemini(GetGeminiApiKey(), GetGeminiModelName(), packageReferences, securityContext);
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

        throw new GeminiConfigurationException(
            "Gemini API key tidak ditemukan. Set environment variable 'GEMINI_API_KEY' atau isi 'Gemini:ApiKey' pada appsettings.local.json/appsettings.json dengan nilai valid.");
    }

    public static string GetGeminiModelName()
    {
        var configuredModelName = Environment.GetEnvironmentVariable(GeminiModelEnvironmentVariableName);

        if (!string.IsNullOrWhiteSpace(configuredModelName))
        {
            return configuredModelName;
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
                !geminiSection.TryGetProperty("Model", out var modelProperty))
            {
                continue;
            }

            var appSettingsModel = modelProperty.GetString();

            if (!string.IsNullOrWhiteSpace(appSettingsModel))
            {
                return appSettingsModel;
            }
        }

        return DefaultGeminiModelName;
    }

    public static async Task<GeminiResponse?> AnalyzeWithGemini(
        string apiKey,
        string modelName,
        IReadOnlyCollection<NuGetPackageReference> packageReferences,
        string securityContext)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(apiKey);
        ArgumentException.ThrowIfNullOrWhiteSpace(modelName);
        ArgumentNullException.ThrowIfNull(packageReferences);
        ArgumentException.ThrowIfNullOrWhiteSpace(securityContext);

        var packageText = BuildPackagePrompt(packageReferences);
        ArgumentException.ThrowIfNullOrWhiteSpace(packageText);

        using var httpClient = new HttpClient();
        httpClient.Timeout = GeminiRequestTimeout;
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
      "MitigationPlan": "string",
      "IsGroundedInReference": true,
      "ReasoningTrace": "string"
    }
  ]
}

Rules:
- Always return a single JSON object.
- Always include the `VulnerabilityReports` array.
- Return one item per package.
- Use empty string for unknown string values.
- Use false for `IsVulnerable` when no known vulnerability is identified.
- Set `IsGroundedInReference` to true only when the finding exists in the provided security reference data.
- If a package is not in the reference, set `IsVulnerable` to false, `IsGroundedInReference` to false, and `Severity` to "Unknown".
- Compare these local packages with the provided security reference data. Only flag vulnerabilities if they exist in the reference. If a package is not in the reference, mark it as Unknown. Provide a mitigation plan based on .NET 8/9 security standards.

Local packages:
{{packageText}}

Security reference data:
{{securityContext}}
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
        try
        {
            using var response = await httpClient.PostAsync($"https://generativelanguage.googleapis.com/v1beta/models/{modelName}:generateContent", content);
            var responseContent = await response.Content.ReadAsStringAsync();

            if (response.StatusCode is HttpStatusCode.Unauthorized or HttpStatusCode.Forbidden)
            {
                throw new GeminiConfigurationException("API key Gemini tidak valid atau tidak memiliki akses ke model yang dipakai.");
            }

            if (response.StatusCode == HttpStatusCode.NotFound)
            {
                throw new GeminiConfigurationException(
                    $"Model Gemini '{modelName}' tidak ditemukan. Coba gunakan model lain seperti '{DefaultGeminiModelName}' melalui environment variable '{GeminiModelEnvironmentVariableName}' atau konfigurasi 'Gemini:Model'. Response: {TruncateForDisplay(responseContent)}");
            }

            response.EnsureSuccessStatusCode();

            var geminiApiResponse = JsonSerializer.Deserialize<GeminiApiResponse>(responseContent, SerializerOptions);
            var json = geminiApiResponse?.Candidates?.FirstOrDefault()?.Content?.Parts?.FirstOrDefault()?.Text;

            if (string.IsNullOrWhiteSpace(json))
            {
                return null;
            }

            return JsonSerializer.Deserialize<GeminiResponse>(ExtractJsonPayload(json), SerializerOptions);
        }
        catch (TaskCanceledException ex)
        {
            throw new TimeoutException($"Permintaan ke Gemini melebihi batas waktu {GeminiRequestTimeout.TotalSeconds:0} detik.", ex);
        }
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

        var fullPath = TryResolveExistingPath(providedPath);

        if (!File.Exists(fullPath))
        {
            throw new FileNotFoundException(
                "File .csproj tidak ditemukan. Gunakan path absolut atau path relatif dari folder project/solution.",
                fullPath);
        }

        return fullPath;
    }

    private static string TryResolveExistingPath(string providedPath)
    {
        if (Path.IsPathRooted(providedPath))
        {
            return Path.GetFullPath(providedPath);
        }

        var searchRoots = GetSearchRoots().ToList();
        var candidatePaths = new List<string>
        {
            Path.GetFullPath(providedPath, Directory.GetCurrentDirectory()),
            Path.GetFullPath(providedPath, AppContext.BaseDirectory)
        };

        foreach (var searchRoot in searchRoots)
        {
            candidatePaths.AddRange(GetParentDirectoryCandidates(searchRoot, providedPath));
        }

        if (!HasDirectorySeparator(providedPath))
        {
            foreach (var searchRoot in searchRoots)
            {
                candidatePaths.AddRange(FindFileByNameUnderDirectory(providedPath, searchRoot));
            }
        }

        return candidatePaths
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .FirstOrDefault(File.Exists)
            ?? Path.GetFullPath(providedPath, Directory.GetCurrentDirectory());
    }

    private static IEnumerable<string> GetParentDirectoryCandidates(string startDirectory, string providedPath)
    {
        var directory = new DirectoryInfo(Path.GetFullPath(startDirectory));

        while (directory is not null)
        {
            yield return Path.Combine(directory.FullName, providedPath);
            directory = directory.Parent;
        }
    }

    private static IEnumerable<string> GetSearchRoots()
    {
        var currentDirectory = new DirectoryInfo(Path.GetFullPath(Directory.GetCurrentDirectory()));
        var baseDirectory = new DirectoryInfo(Path.GetFullPath(AppContext.BaseDirectory));

        return new[]
        {
            FindWorkspaceRoot(currentDirectory)?.FullName,
            FindWorkspaceRoot(baseDirectory)?.FullName,
            currentDirectory.FullName,
            baseDirectory.FullName
        }
        .Where(x => !string.IsNullOrWhiteSpace(x))
        .Distinct(StringComparer.OrdinalIgnoreCase)!;
    }

    private static DirectoryInfo? FindWorkspaceRoot(DirectoryInfo? startDirectory)
    {
        var directory = startDirectory;

        while (directory is not null)
        {
            var hasGitDirectory = Directory.Exists(Path.Combine(directory.FullName, ".git"));
            var hasSolutionFile = Directory.EnumerateFiles(directory.FullName, "*.sln", SearchOption.TopDirectoryOnly).Any();
            var hasProjectFile = Directory.EnumerateFiles(directory.FullName, "*.csproj", SearchOption.TopDirectoryOnly).Any();

            if (hasGitDirectory || hasSolutionFile || hasProjectFile)
            {
                return directory;
            }

            directory = directory.Parent;
        }

        return startDirectory;
    }

    private static IEnumerable<string> FindFileByNameUnderDirectory(string fileName, string rootDirectory)
    {
        var pendingDirectories = new Stack<string>();
        pendingDirectories.Push(Path.GetFullPath(rootDirectory));

        while (pendingDirectories.Count > 0)
        {
            var currentDirectory = pendingDirectories.Pop();
            string[] fileMatches;
            string[] childDirectories;

            try
            {
                fileMatches = Directory.GetFiles(currentDirectory, fileName, SearchOption.TopDirectoryOnly);
                childDirectories = Directory.GetDirectories(currentDirectory, "*", SearchOption.TopDirectoryOnly);
            }
            catch (UnauthorizedAccessException)
            {
                continue;
            }
            catch (DirectoryNotFoundException)
            {
                continue;
            }

            foreach (var match in fileMatches)
            {
                yield return match;
            }

            foreach (var childDirectory in childDirectories)
            {
                pendingDirectories.Push(childDirectory);
            }
        }
    }

    private static bool HasDirectorySeparator(string path)
    {
        return path.Contains(Path.DirectorySeparatorChar) || path.Contains(Path.AltDirectorySeparatorChar);
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
        string modelName,
        IReadOnlyCollection<NuGetPackageReference> packageReferences,
        GeminiResponse geminiResponse)
    {
        var outputDirectory = Path.Combine(GetApplicationRootDirectory(), "audit-results");
        Directory.CreateDirectory(outputDirectory);

        var outputFilePath = Path.Combine(
            outputDirectory,
            $"audit-{Path.GetFileNameWithoutExtension(csprojPath)}-{DateTime.UtcNow:yyyyMMdd-HHmmss}.json");

        var sessionRecord = new AuditSessionRecord
        {
            GeneratedAtUtc = DateTimeOffset.UtcNow,
            SourceProjectPath = csprojPath,
            ModelName = modelName,
            ExtractedPackages = packageReferences.ToList(),
            VulnerabilityReports = geminiResponse.VulnerabilityReports
        };

        File.WriteAllText(outputFilePath, JsonSerializer.Serialize(sessionRecord, SerializerOptions));
        return outputFilePath;
    }

    private static string SaveScanMetricsCsv(
        string csprojPath,
        GeminiResponse geminiResponse,
        string securityContext)
    {
        var outputDirectory = Path.Combine(GetApplicationRootDirectory(), "audit-results");
        Directory.CreateDirectory(outputDirectory);

        var projectName = Path.GetFileNameWithoutExtension(csprojPath);
        var outputFilePath = Path.Combine(
            outputDirectory,
            $"metrics-{projectName}-{DateTime.UtcNow:yyyyMMdd-HHmmss}.csv");

        var referencedPackages = ExtractReferencedPackageNames(securityContext);
        var builder = new StringBuilder();
        builder.AppendLine("ProjectName,PackageName,Gemini_Detected,Reference_Exists,Match_Result");

        foreach (var report in geminiResponse.VulnerabilityReports)
        {
            var packageName = report.PackageName ?? string.Empty;
            var geminiDetected = report.IsVulnerable;
            var referenceExists = !string.IsNullOrWhiteSpace(packageName) && referencedPackages.Contains(packageName);
            var matchResult = GetMatchResult(geminiDetected, referenceExists);

            builder.AppendLine(string.Join(",",
                EscapeCsv(projectName),
                EscapeCsv(packageName),
                geminiDetected ? "true" : "false",
                referenceExists ? "true" : "false",
                EscapeCsv(matchResult)));
        }

        File.WriteAllText(outputFilePath, builder.ToString());
        return outputFilePath;
    }

    private static HashSet<string> ExtractReferencedPackageNames(string securityContext)
    {
        var result = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        if (string.IsNullOrWhiteSpace(securityContext))
        {
            return result;
        }

        using var document = JsonDocument.Parse(securityContext);

        foreach (var advisory in GetAdvisoriesFromSecurityContext(document.RootElement))
        {
            var packageName = TryGetPackageNameFromSecurityContext(advisory);

            if (!string.IsNullOrWhiteSpace(packageName))
            {
                result.Add(packageName);
            }
        }

        return result;
    }

    private static IEnumerable<JsonElement> GetAdvisoriesFromSecurityContext(JsonElement root)
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

    private static string TryGetPackageNameFromSecurityContext(JsonElement advisory)
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

    private static string GetMatchResult(bool geminiDetected, bool referenceExists)
    {
        if (geminiDetected && referenceExists)
        {
            return "True Positive";
        }

        if (geminiDetected && !referenceExists)
        {
            return "False Positive";
        }

        if (!geminiDetected && referenceExists)
        {
            return "False Negative";
        }

        return "True Negative";
    }

    private static string EscapeCsv(string value)
    {
        var safeValue = value ?? string.Empty;

        if (!safeValue.Contains(',') && !safeValue.Contains('"') && !safeValue.Contains('\n') && !safeValue.Contains('\r'))
        {
            return safeValue;
        }

        return $"\"{safeValue.Replace("\"", "\"\"")}\"";
    }

    private static string GetApplicationRootDirectory()
    {
        var currentDirectoryRoot = FindWorkspaceRoot(new DirectoryInfo(Path.GetFullPath(Directory.GetCurrentDirectory())));

        if (currentDirectoryRoot is not null)
        {
            return currentDirectoryRoot.FullName;
        }

        var baseDirectoryRoot = FindWorkspaceRoot(new DirectoryInfo(Path.GetFullPath(AppContext.BaseDirectory)));
        return baseDirectoryRoot?.FullName ?? Directory.GetCurrentDirectory();
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

    private static string FormatElapsed(TimeSpan elapsed)
    {
        return $"{elapsed.TotalSeconds:F2}s";
    }

    private static string TruncateForDisplay(string value, int maxLength = 300)
    {
        if (string.IsNullOrWhiteSpace(value) || value.Length <= maxLength)
        {
            return value;
        }

        return value[..maxLength] + "...";
    }

    private sealed class GeminiConfigurationException(string message) : Exception(message)
    {
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
