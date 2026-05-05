using System.Diagnostics;
using System.Net;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using ClosedXML.Excel;

namespace GeminiNuGetAuditor;

public class Program
{
    private const string GeminiApiKeyEnvironmentVariableName = "GEMINI_API_KEY";
    private const string GeminiModelEnvironmentVariableName = "GEMINI_MODEL";

    private static readonly JsonDocumentOptions AppSettingsJsonOptions = new()
    {
        CommentHandling = JsonCommentHandling.Skip,
        AllowTrailingCommas = true
    };

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
            var geminiSettings = GetGeminiSettings();
            var csprojPath = ResolveCsprojPath(args);
            var modelName = GetGeminiModelName(geminiSettings);
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
            Console.WriteLine("Retrieving security reference context...");
            var securityContextResult = SecurityReferenceProvider.GetSecurityContextWithDiagnostics(
                packageReferences.Select(x => x.PackageName).ToList());

            Console.WriteLine($"Security reference source: {securityContextResult.Source}");

            foreach (var detail in securityContextResult.Diagnostics)
            {
                Console.WriteLine($"[Retrieval] {detail}");
            }

            var securityContext = securityContextResult.Context;
            Console.WriteLine("Sending package list to Gemini for security analysis...");

            var analysisStopwatch = Stopwatch.StartNew();
            var geminiResponse = await AnalyzeWithGeminiWithBatching(
                GetGeminiApiKey(geminiSettings),
                modelName,
                packageReferences,
                securityContext,
                geminiSettings);
            analysisStopwatch.Stop();

            Console.WriteLine($"Gemini analysis completed in {FormatElapsed(analysisStopwatch.Elapsed)}.");
            Console.WriteLine("Gemini response received. Normalizing audit results...");

            var postProcessingStopwatch = Stopwatch.StartNew();
            var normalizedResponse = NormalizeResponse(packageReferences, geminiResponse);
            Console.WriteLine("Saving audit dataset to local JSON file...");
            var outputPath = SaveAuditResult(csprojPath, modelName, packageReferences, normalizedResponse);
            var metricsExcelPath = SaveScanMetricsExcel(csprojPath, normalizedResponse, securityContext);
            postProcessingStopwatch.Stop();

            var vulnerableCount = normalizedResponse.VulnerabilityReports.Count(x => x.IsVulnerable);
            totalStopwatch.Stop();

            Console.WriteLine($"Audit completed. {packageReferences.Count} package(s) were analyzed.");
            Console.WriteLine($"Potentially vulnerable packages detected: {vulnerableCount}.");
            Console.WriteLine($"Post-processing completed in {FormatElapsed(postProcessingStopwatch.Elapsed)}.");
            Console.WriteLine($"Total execution time: {FormatElapsed(totalStopwatch.Elapsed)}.");
            Console.WriteLine($"Audit result saved to: {outputPath}");
            Console.WriteLine($"Metrics Excel saved to: {metricsExcelPath}");
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
        var geminiSettings = GetGeminiSettings();
        return AnalyzeWithGemini(
            GetGeminiApiKey(geminiSettings),
            GetGeminiModelName(geminiSettings),
            packageReferences,
            securityContext,
            geminiSettings);
    }

    public static string GetGeminiApiKey()
    {
        return GetGeminiApiKey(GetGeminiSettings());
    }

    public static string GetGeminiModelName()
    {
        return GetGeminiModelName(GetGeminiSettings());
    }

    private static string GetGeminiApiKey(GeminiSettings settings)
    {
        var apiKey = Environment.GetEnvironmentVariable(GeminiApiKeyEnvironmentVariableName);

        if (IsUsableApiKey(apiKey))
        {
            return apiKey!;
        }

        if (IsUsableApiKey(settings.ApiKey))
        {
            return settings.ApiKey;
        }

        throw new GeminiConfigurationException(
            $"Gemini API key tidak ditemukan. Set environment variable '{GeminiApiKeyEnvironmentVariableName}' atau isi 'Gemini:ApiKey' pada appsettings.json dengan nilai valid.");
    }

    private static string GetGeminiModelName(GeminiSettings settings)
    {
        var configuredModelName = Environment.GetEnvironmentVariable(GeminiModelEnvironmentVariableName);

        if (!string.IsNullOrWhiteSpace(configuredModelName))
        {
            return configuredModelName;
        }

        if (!string.IsNullOrWhiteSpace(settings.Model))
        {
            return settings.Model;
        }

        throw new GeminiConfigurationException("Konfigurasi model Gemini tidak valid. Isi 'Gemini:Model'.");
    }

    private static async Task<GeminiResponse?> AnalyzeWithGeminiWithBatching(
        string apiKey,
        string modelName,
        IReadOnlyCollection<NuGetPackageReference> packageReferences,
        string securityContext,
        GeminiSettings settings)
    {
        if (packageReferences.Count <= settings.MaxPackagesPerRequest)
        {
            var scopedSecurityContext = FilterSecurityContextForPackages(securityContext, packageReferences.Select(x => x.PackageName));
            return await AnalyzeWithGeminiWithRetry(apiKey, modelName, packageReferences, scopedSecurityContext, settings);
        }

        var batches = packageReferences.Chunk(settings.MaxPackagesPerRequest).ToList();
        Console.WriteLine($"[Gemini] Large package list detected. Using batching: {batches.Count} batch(es), up to {settings.MaxPackagesPerRequest} package(s) per batch.");

        var mergedReports = new List<VulnerabilityReport>();

        for (var i = 0; i < batches.Count; i++)
        {
            var batch = batches[i];
            var scopedSecurityContext = FilterSecurityContextForPackages(securityContext, batch.Select(x => x.PackageName));

            Console.WriteLine($"[Gemini] Processing batch {i + 1}/{batches.Count} ({batch.Length} package(s)). Security context chars={scopedSecurityContext.Length}.");
            var batchResponse = await AnalyzeWithGeminiWithRetry(apiKey, modelName, batch, scopedSecurityContext, settings);

            if (batchResponse?.VulnerabilityReports is { Count: > 0 })
            {
                mergedReports.AddRange(batchResponse.VulnerabilityReports);
            }
        }

        return new GeminiResponse
        {
            VulnerabilityReports = mergedReports
        };
    }

    private static async Task<GeminiResponse?> AnalyzeWithGeminiWithRetry(
        string apiKey,
        string modelName,
        IReadOnlyCollection<NuGetPackageReference> packageReferences,
        string securityContext,
        GeminiSettings settings)
    {
        var maxAttempts = settings.MaxRetryCount + 1;

        for (var attempt = 1; attempt <= maxAttempts; attempt++)
        {
            try
            {
                return await AnalyzeWithGemini(apiKey, modelName, packageReferences, securityContext, settings);
            }
            catch (TimeoutException) when (attempt < maxAttempts)
            {
                var delay = settings.RetryDelayMilliseconds * attempt;
                Console.WriteLine($"[Gemini] Timeout at attempt {attempt}/{maxAttempts}. Retrying in {delay}ms...");
                await Task.Delay(delay);
            }
            catch (HttpRequestException ex) when (attempt < maxAttempts && IsTransientStatusCode(ex.StatusCode))
            {
                var delay = settings.RetryDelayMilliseconds * attempt;
                Console.WriteLine($"[Gemini] Transient HTTP error at attempt {attempt}/{maxAttempts}: {ex.StatusCode}. Retrying in {delay}ms...");
                await Task.Delay(delay);
            }
        }

        return null;
    }

    private static bool IsTransientStatusCode(HttpStatusCode? statusCode)
    {
        if (!statusCode.HasValue)
        {
            return true;
        }

        return statusCode == HttpStatusCode.TooManyRequests || (int)statusCode.Value >= 500;
    }

    private static string FilterSecurityContextForPackages(string securityContext, IEnumerable<string> packageNames)
    {
        if (string.IsNullOrWhiteSpace(securityContext))
        {
            return "[]";
        }

        var packageSet = new HashSet<string>(
            packageNames.Where(x => !string.IsNullOrWhiteSpace(x)).Select(x => x.Trim()),
            StringComparer.OrdinalIgnoreCase);

        if (packageSet.Count == 0)
        {
            return "[]";
        }

        using var document = JsonDocument.Parse(securityContext, AppSettingsJsonOptions);
        var matched = new List<JsonElement>();

        foreach (var advisory in GetAdvisoriesFromSecurityContext(document.RootElement))
        {
            var packageName = TryGetPackageNameFromSecurityContext(advisory);

            if (!string.IsNullOrWhiteSpace(packageName) && packageSet.Contains(packageName))
            {
                matched.Add(advisory.Clone());
            }
        }

        return JsonSerializer.Serialize(matched, SerializerOptions);
    }

    private static async Task<GeminiResponse?> AnalyzeWithGemini(
        string apiKey,
        string modelName,
        IReadOnlyCollection<NuGetPackageReference> packageReferences,
        string securityContext,
        GeminiSettings settings)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(apiKey);
        ArgumentException.ThrowIfNullOrWhiteSpace(modelName);
        ArgumentNullException.ThrowIfNull(packageReferences);
        ArgumentException.ThrowIfNullOrWhiteSpace(securityContext);
        ArgumentNullException.ThrowIfNull(settings);

        var packageText = BuildPackagePrompt(packageReferences);
        ArgumentException.ThrowIfNullOrWhiteSpace(packageText);

        using var httpClient = new HttpClient();
        httpClient.Timeout = TimeSpan.FromSeconds(settings.RequestTimeoutSeconds);
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
      "SeverityIndonesia": "string",
      "MitigationPlan": "string",
      "MitigationPlanIndonesia": "string",
      "IsGroundedInReference": true,
      "ReasoningTrace": "string",
      "ReasoningTraceIndonesia": "string"
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
- If a package is not in the reference, set `IsVulnerable` to false, `IsGroundedInReference` to false, and `Severity`/`SeverityIndonesia` to "Unknown"/"Tidak diketahui".
- Always fill bilingual fields: English and Indonesian versions for severity, mitigation plan, and reasoning trace.
- Compare these local packages with the provided security reference data. Only flag vulnerabilities if they exist in the reference. If a package is not in the reference, mark it as Unknown. Provide a mitigation plan based on .NET 10 security standards.

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
            var endpoint = string.Format(settings.GenerateContentEndpointTemplate, modelName);
            Console.WriteLine($"[Gemini] Endpoint: {endpoint}");
            using var response = await httpClient.PostAsync(endpoint, content);
            Console.WriteLine($"[Gemini] HTTP {(int)response.StatusCode} ({response.StatusCode})");
            var responseContent = await response.Content.ReadAsStringAsync();

            if (response.StatusCode is HttpStatusCode.Unauthorized or HttpStatusCode.Forbidden)
            {
                throw new GeminiConfigurationException("API key Gemini tidak valid atau tidak memiliki akses ke model yang dipakai.");
            }

            if (response.StatusCode == HttpStatusCode.NotFound)
            {
                throw new GeminiConfigurationException(
                    $"Model Gemini '{modelName}' tidak ditemukan. Coba gunakan model lain melalui environment variable '{GeminiModelEnvironmentVariableName}' atau konfigurasi 'Gemini:Model'. Response: {TruncateForDisplay(responseContent)}");
            }

            response.EnsureSuccessStatusCode();

            var geminiApiResponse = JsonSerializer.Deserialize<GeminiApiResponse>(responseContent, SerializerOptions);
            var json = geminiApiResponse?.Candidates?.FirstOrDefault()?.Content?.Parts?.FirstOrDefault()?.Text;

            if (string.IsNullOrWhiteSpace(json))
            {
                Console.WriteLine("[Gemini] Response payload is empty.");
                return null;
            }

            Console.WriteLine("[Gemini] Response payload parsed successfully.");
            return JsonSerializer.Deserialize<GeminiResponse>(ExtractJsonPayload(json), SerializerOptions);
        }
        catch (TaskCanceledException ex)
        {
            throw new TimeoutException($"Permintaan ke Gemini melebihi batas waktu {settings.RequestTimeoutSeconds:0} detik.", ex);
        }
    }

    private static GeminiSettings GetGeminiSettings()
    {
        var settings = new GeminiSettings();

        foreach (var appSettingsPath in GetAppSettingsPaths())
        {
            if (!File.Exists(appSettingsPath))
            {
                continue;
            }

            using var stream = File.OpenRead(appSettingsPath);
            using var document = JsonDocument.Parse(stream, AppSettingsJsonOptions);

            if (!document.RootElement.TryGetProperty("Gemini", out var geminiSection) || geminiSection.ValueKind != JsonValueKind.Object)
            {
                continue;
            }

            settings.ApiKey = ReadGeminiString(geminiSection, "ApiKey", settings.ApiKey);
            settings.Model = ReadGeminiString(geminiSection, "Model", settings.Model);
            settings.GenerateContentEndpointTemplate = ReadGeminiString(geminiSection, "GenerateContentEndpointTemplate", settings.GenerateContentEndpointTemplate);
            settings.RequestTimeoutSeconds = ReadGeminiInt(geminiSection, "RequestTimeoutSeconds", settings.RequestTimeoutSeconds);
            settings.MaxPackagesPerRequest = ReadGeminiInt(geminiSection, "MaxPackagesPerRequest", settings.MaxPackagesPerRequest);
            settings.MaxRetryCount = ReadGeminiInt(geminiSection, "MaxRetryCount", settings.MaxRetryCount);
            settings.RetryDelayMilliseconds = ReadGeminiInt(geminiSection, "RetryDelayMilliseconds", settings.RetryDelayMilliseconds);
        }

        ValidateGeminiSettings(settings);
        return settings;
    }

    private static void ValidateGeminiSettings(GeminiSettings settings)
    {
        if (string.IsNullOrWhiteSpace(settings.Model))
        {
            throw new GeminiConfigurationException("Konfigurasi 'Gemini:Model' wajib diisi.");
        }

        if (string.IsNullOrWhiteSpace(settings.GenerateContentEndpointTemplate) || !settings.GenerateContentEndpointTemplate.Contains("{0}", StringComparison.Ordinal))
        {
            throw new GeminiConfigurationException("Konfigurasi 'Gemini:GenerateContentEndpointTemplate' wajib diisi dan harus mengandung placeholder '{0}' untuk nama model.");
        }

        if (settings.RequestTimeoutSeconds <= 0)
        {
            throw new GeminiConfigurationException("Konfigurasi 'Gemini:RequestTimeoutSeconds' harus lebih besar dari 0.");
        }

        if (settings.MaxPackagesPerRequest <= 0)
        {
            throw new GeminiConfigurationException("Konfigurasi 'Gemini:MaxPackagesPerRequest' harus lebih besar dari 0.");
        }

        if (settings.MaxRetryCount < 0)
        {
            throw new GeminiConfigurationException("Konfigurasi 'Gemini:MaxRetryCount' tidak boleh negatif.");
        }

        if (settings.RetryDelayMilliseconds <= 0)
        {
            throw new GeminiConfigurationException("Konfigurasi 'Gemini:RetryDelayMilliseconds' harus lebih besar dari 0.");
        }
    }

    private static string ReadGeminiString(JsonElement section, string propertyName, string currentValue)
    {
        if (!section.TryGetProperty(propertyName, out var property) || property.ValueKind != JsonValueKind.String)
        {
            return currentValue;
        }

        var value = property.GetString();
        return string.IsNullOrWhiteSpace(value) ? currentValue : value;
    }

    private static int ReadGeminiInt(JsonElement section, string propertyName, int currentValue)
    {
        if (!section.TryGetProperty(propertyName, out var property) || property.ValueKind != JsonValueKind.Number)
        {
            return currentValue;
        }

        return property.TryGetInt32(out var value) ? value : currentValue;
    }

    private static IEnumerable<string> GetAppSettingsPaths()
    {
        var baseDirectoryPath = Path.Combine(AppContext.BaseDirectory, "appsettings.json");
        yield return baseDirectoryPath;

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
                    report.SeverityIndonesia ??= string.Empty;
                    report.MitigationPlan ??= string.Empty;
                    report.MitigationPlanIndonesia ??= string.Empty;
                    report.ReasoningTrace ??= string.Empty;
                    report.ReasoningTraceIndonesia ??= string.Empty;
                    return report;
                }

                return new VulnerabilityReport
                {
                    PackageName = packageReference.PackageName,
                    CurrentVersion = packageReference.CurrentVersion,
                    IsVulnerable = false,
                    CVE_ID = string.Empty,
                    Severity = string.Empty,
                    SeverityIndonesia = string.Empty,
                    MitigationPlan = string.Empty,
                    MitigationPlanIndonesia = string.Empty,
                    ReasoningTrace = string.Empty,
                    ReasoningTraceIndonesia = string.Empty
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
            VulnerabilityReports = geminiResponse.VulnerabilityReports,
            VulnerabilityReportFieldDescriptions = GetVulnerabilityReportFieldDescriptions()
        };

        File.WriteAllText(outputFilePath, JsonSerializer.Serialize(sessionRecord, SerializerOptions));
        return outputFilePath;
    }

    private static string SaveScanMetricsExcel(
        string csprojPath,
        GeminiResponse geminiResponse,
        string securityContext)
    {
        var outputDirectory = Path.Combine(GetApplicationRootDirectory(), "audit-results");
        Directory.CreateDirectory(outputDirectory);

        var projectName = Path.GetFileNameWithoutExtension(csprojPath);
        var outputFilePath = Path.Combine(
            outputDirectory,
            $"metrics-{projectName}-{DateTime.UtcNow:yyyyMMdd-HHmmss}.xlsx");

        var referencedPackages = ExtractReferencedPackageNames(securityContext);

        using var workbook = new XLWorkbook();

        var detailSheet = workbook.Worksheets.Add("Detail");
        detailSheet.Cell(1, 1).Value = "ProjectName";
        detailSheet.Cell(1, 2).Value = "PackageName";
        detailSheet.Cell(1, 3).Value = "CurrentVersion";
        detailSheet.Cell(1, 4).Value = "Gemini_Detected";
        detailSheet.Cell(1, 5).Value = "Reference_Exists";
        detailSheet.Cell(1, 6).Value = "Match_Result";
        detailSheet.Cell(1, 7).Value = "Severity";
        detailSheet.Cell(1, 8).Value = "CVE_ID";
        detailSheet.Cell(1, 9).Value = "Grounded";

        var row = 2;

        foreach (var report in geminiResponse.VulnerabilityReports)
        {
            var packageName = report.PackageName ?? string.Empty;
            var geminiDetected = report.IsVulnerable;
            var referenceExists = !string.IsNullOrWhiteSpace(packageName) && referencedPackages.Contains(packageName);
            var matchResult = GetMatchResult(geminiDetected, referenceExists);

            detailSheet.Cell(row, 1).Value = projectName;
            detailSheet.Cell(row, 2).Value = packageName;
            detailSheet.Cell(row, 3).Value = report.CurrentVersion ?? string.Empty;
            detailSheet.Cell(row, 4).Value = geminiDetected ? "true" : "false";
            detailSheet.Cell(row, 5).Value = referenceExists ? "true" : "false";
            detailSheet.Cell(row, 6).Value = matchResult;
            detailSheet.Cell(row, 7).Value = report.Severity ?? string.Empty;
            detailSheet.Cell(row, 8).Value = report.CVE_ID ?? string.Empty;
            detailSheet.Cell(row, 9).Value = report.IsGroundedInReference ? "true" : "false";
            row++;
        }

        var detailHeaderRange = detailSheet.Range(1, 1, 1, 9);
        detailHeaderRange.Style.Font.Bold = true;
        detailHeaderRange.Style.Fill.BackgroundColor = XLColor.LightGray;
        detailSheet.SheetView.FreezeRows(1);

        var detailDataRange = detailSheet.Range(2, 1, Math.Max(2, row - 1), 9);
        detailDataRange.SetAutoFilter();

        for (var i = 2; i < row; i++)
        {
            var matchValue = detailSheet.Cell(i, 6).GetString();
            if (matchValue == "False Positive" || matchValue == "False Negative")
            {
                detailSheet.Range(i, 1, i, 9).Style.Fill.BackgroundColor = XLColor.LightPink;
            }
            else if (matchValue == "True Positive")
            {
                detailSheet.Range(i, 1, i, 9).Style.Fill.BackgroundColor = XLColor.LightGoldenrodYellow;
            }
        }

        detailSheet.Columns().AdjustToContents();

        var summarySheet = workbook.Worksheets.Add("Summary");
        var total = geminiResponse.VulnerabilityReports.Count;
        var truePositive = geminiResponse.VulnerabilityReports.Count(x => x.IsVulnerable && referencedPackages.Contains(x.PackageName ?? string.Empty));
        var falsePositive = geminiResponse.VulnerabilityReports.Count(x => x.IsVulnerable && !referencedPackages.Contains(x.PackageName ?? string.Empty));
        var falseNegative = geminiResponse.VulnerabilityReports.Count(x => !x.IsVulnerable && referencedPackages.Contains(x.PackageName ?? string.Empty));
        var trueNegative = total - truePositive - falsePositive - falseNegative;
        var groundedCount = geminiResponse.VulnerabilityReports.Count(x => x.IsGroundedInReference);

        summarySheet.Cell(1, 1).Value = "Audit Metrics Summary";
        summarySheet.Cell(1, 1).Style.Font.Bold = true;
        summarySheet.Cell(1, 1).Style.Font.FontSize = 16;

        summarySheet.Cell(3, 1).Value = "Project";
        summarySheet.Cell(3, 2).Value = projectName;
        summarySheet.Cell(4, 1).Value = "Total Packages";
        summarySheet.Cell(4, 2).Value = total;
        summarySheet.Cell(5, 1).Value = "Reference Packages";
        summarySheet.Cell(5, 2).Value = referencedPackages.Count;
        summarySheet.Cell(6, 1).Value = "Detected Vulnerable";
        summarySheet.Cell(6, 2).Value = geminiResponse.VulnerabilityReports.Count(x => x.IsVulnerable);
        summarySheet.Cell(7, 1).Value = "Grounded Findings";
        summarySheet.Cell(7, 2).Value = groundedCount;

        summarySheet.Cell(9, 1).Value = "Confusion Matrix";
        summarySheet.Cell(9, 1).Style.Font.Bold = true;

        summarySheet.Cell(10, 1).Value = "True Positive";
        summarySheet.Cell(10, 2).Value = truePositive;
        summarySheet.Cell(11, 1).Value = "False Positive";
        summarySheet.Cell(11, 2).Value = falsePositive;
        summarySheet.Cell(12, 1).Value = "False Negative";
        summarySheet.Cell(12, 2).Value = falseNegative;
        summarySheet.Cell(13, 1).Value = "True Negative";
        summarySheet.Cell(13, 2).Value = trueNegative;

        var accuracy = total > 0 ? (double)(truePositive + trueNegative) / total : 0d;
        var precisionDenominator = truePositive + falsePositive;
        var recallDenominator = truePositive + falseNegative;
        var precision = precisionDenominator > 0 ? (double)truePositive / precisionDenominator : 0d;
        var recall = recallDenominator > 0 ? (double)truePositive / recallDenominator : 0d;
        var f1Denominator = precision + recall;
        var f1 = f1Denominator > 0 ? 2 * precision * recall / f1Denominator : 0d;

        summarySheet.Cell(15, 1).Value = "Accuracy";
        summarySheet.Cell(15, 2).Value = accuracy;
        summarySheet.Cell(16, 1).Value = "Precision";
        summarySheet.Cell(16, 2).Value = precision;
        summarySheet.Cell(17, 1).Value = "Recall";
        summarySheet.Cell(17, 2).Value = recall;
        summarySheet.Cell(18, 1).Value = "F1-Score";
        summarySheet.Cell(18, 2).Value = f1;

        summarySheet.Range(15, 2, 18, 2).Style.NumberFormat.Format = "0.00%";
        summarySheet.Columns().AdjustToContents();

        var summaryDetailSheet = workbook.Worksheets.Add("Summary Details");
        summaryDetailSheet.Cell(1, 1).Value = "Metric";
        summaryDetailSheet.Cell(1, 2).Value = "Value";
        summaryDetailSheet.Cell(1, 3).Value = "Description";

        var summaryDetails = new List<(string Metric, string Value, string Description)>
        {
            ("Project", projectName, "Nama project target yang diaudit."),
            ("Total Packages", total.ToString(), "Jumlah total package yang dianalisis."),
            ("Reference Packages", referencedPackages.Count.ToString(), "Jumlah package yang ditemukan pada security reference context."),
            ("Detected Vulnerable", geminiResponse.VulnerabilityReports.Count(x => x.IsVulnerable).ToString(), "Jumlah package yang ditandai rentan oleh hasil analisis."),
            ("Grounded Findings", groundedCount.ToString(), "Jumlah temuan dengan IsGroundedInReference = true."),
            ("True Positive", truePositive.ToString(), "Model menandai rentan dan package memang ada di referensi kerentanan."),
            ("False Positive", falsePositive.ToString(), "Model menandai rentan tetapi package tidak ada di referensi kerentanan."),
            ("False Negative", falseNegative.ToString(), "Model tidak menandai rentan padahal package ada di referensi kerentanan."),
            ("True Negative", trueNegative.ToString(), "Model tidak menandai rentan dan package memang tidak ada di referensi kerentanan."),
            ("Accuracy", $"{accuracy:P2}", "Proporsi prediksi benar dari seluruh package: (TP + TN) / Total."),
            ("Precision", $"{precision:P2}", "Ketepatan prediksi rentan: TP / (TP + FP)."),
            ("Recall", $"{recall:P2}", "Kemampuan menangkap package rentan: TP / (TP + FN)."),
            ("F1-Score", $"{f1:P2}", "Rata-rata harmonik Precision dan Recall: 2PR / (P + R).")
        };

        var detailRow = 2;
        foreach (var item in summaryDetails)
        {
            summaryDetailSheet.Cell(detailRow, 1).Value = item.Metric;
            summaryDetailSheet.Cell(detailRow, 2).Value = item.Value;
            summaryDetailSheet.Cell(detailRow, 3).Value = item.Description;
            detailRow++;
        }

        var summaryDetailHeader = summaryDetailSheet.Range(1, 1, 1, 3);
        summaryDetailHeader.Style.Font.Bold = true;
        summaryDetailHeader.Style.Fill.BackgroundColor = XLColor.LightGray;
        summaryDetailSheet.SheetView.FreezeRows(1);
        summaryDetailSheet.Range(2, 1, Math.Max(2, detailRow - 1), 3).SetAutoFilter();
        summaryDetailSheet.Columns().AdjustToContents();

        workbook.SaveAs(outputFilePath);
        return outputFilePath;
    }

    private static string SaveScanMetricsCsv(
        string csprojPath,
        GeminiResponse geminiResponse,
        string securityContext)
    {
        return SaveScanMetricsExcel(csprojPath, geminiResponse, securityContext);
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
        return !string.IsNullOrWhiteSpace(apiKey);
    }

    private static Dictionary<string, VulnerabilityFieldDescription> GetVulnerabilityReportFieldDescriptions()
    {
        return new Dictionary<string, VulnerabilityFieldDescription>
        {
            ["PackageName"] = new VulnerabilityFieldDescription
            {
                Description = "Nama paket NuGet yang dianalisis."
            },
            ["CurrentVersion"] = new VulnerabilityFieldDescription
            {
                Description = "Versi paket yang saat ini digunakan pada proyek target."
            },
            ["IsVulnerable"] = new VulnerabilityFieldDescription
            {
                Description = "Status apakah paket terdeteksi rentan berdasarkan analisis.",
                ValueDescriptions = new Dictionary<string, string>
                {
                    ["true"] = "Paket terindikasi memiliki kerentanan.",
                    ["false"] = "Tidak ada kerentanan yang teridentifikasi untuk paket ini pada referensi yang tersedia."
                }
            },
            ["CVE_ID"] = new VulnerabilityFieldDescription
            {
                Description = "Identifier CVE yang terkait dengan kerentanan, jika tersedia."
            },
            ["Severity"] = new VulnerabilityFieldDescription
            {
                Description = "Tingkat keparahan kerentanan dalam bahasa Inggris.",
                ValueDescriptions = new Dictionary<string, string>
                {
                    ["CRITICAL"] = "Kerentanan sangat parah dengan dampak tinggi; perlu tindakan segera.",
                    ["HIGH"] = "Kerentanan parah dengan risiko tinggi; disarankan mitigasi secepatnya.",
                    ["MODERATE"] = "Kerentanan tingkat sedang; perlu mitigasi terencana.",
                    ["LOW"] = "Kerentanan tingkat rendah; dampak terbatas namun tetap perlu diperhatikan.",
                    ["Unknown"] = "Tingkat keparahan tidak dapat dipastikan dari referensi yang tersedia.",
                    [""] = "Nilai tidak diisi oleh model."
                }
            },
            ["SeverityIndonesia"] = new VulnerabilityFieldDescription
            {
                Description = "Tingkat keparahan kerentanan dalam bahasa Indonesia.",
                ValueDescriptions = new Dictionary<string, string>
                {
                    ["Kritis"] = "Kerentanan sangat parah dengan dampak tinggi; perlu tindakan segera.",
                    ["Tinggi"] = "Kerentanan parah dengan risiko tinggi; disarankan mitigasi secepatnya.",
                    ["Sedang"] = "Kerentanan tingkat sedang; perlu mitigasi terencana.",
                    ["Rendah"] = "Kerentanan tingkat rendah; dampak terbatas namun tetap perlu diperhatikan.",
                    ["Tidak diketahui"] = "Tingkat keparahan tidak dapat dipastikan dari referensi yang tersedia.",
                    [""] = "Nilai tidak diisi oleh model."
                }
            },
            ["MitigationPlan"] = new VulnerabilityFieldDescription
            {
                Description = "Rencana mitigasi atau rekomendasi perbaikan dalam bahasa Inggris."
            },
            ["MitigationPlanIndonesia"] = new VulnerabilityFieldDescription
            {
                Description = "Rencana mitigasi atau rekomendasi perbaikan dalam bahasa Indonesia."
            },
            ["IsGroundedInReference"] = new VulnerabilityFieldDescription
            {
                Description = "Status apakah temuan didukung oleh data referensi keamanan yang diberikan.",
                ValueDescriptions = new Dictionary<string, string>
                {
                    ["true"] = "Temuan didukung data referensi keamanan (misalnya advisory/CVE dari konteks referensi).",
                    ["false"] = "Temuan tidak didukung langsung data referensi keamanan yang diberikan; perlu verifikasi lanjutan."
                }
            },
            ["ReasoningTrace"] = new VulnerabilityFieldDescription
            {
                Description = "Ringkasan alasan analisis model dalam bahasa Inggris."
            },
            ["ReasoningTraceIndonesia"] = new VulnerabilityFieldDescription
            {
                Description = "Ringkasan alasan analisis model dalam bahasa Indonesia."
            }
        };
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

        if (jsonStartIndex < 0)
        {
            return trimmedResponse;
        }

        var candidateJson = trimmedResponse[jsonStartIndex..];

        try
        {
            var utf8 = Encoding.UTF8.GetBytes(candidateJson);
            var reader = new Utf8JsonReader(utf8, isFinalBlock: true, state: default);
            using var _ = JsonDocument.ParseValue(ref reader);
            var bytesConsumed = (int)reader.BytesConsumed;

            if (bytesConsumed > 0)
            {
                return candidateJson[..bytesConsumed];
            }
        }
        catch
        {
        }

        var jsonEndIndex = trimmedResponse.LastIndexOf('}');

        if (jsonEndIndex >= jsonStartIndex)
        {
            return trimmedResponse.Substring(jsonStartIndex, jsonEndIndex - jsonStartIndex + 1);
        }

        return candidateJson;
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

    private sealed class GeminiSettings
    {
        public string ApiKey { get; set; } = string.Empty;
        public string Model { get; set; } = string.Empty;
        public string GenerateContentEndpointTemplate { get; set; } = string.Empty;
        public int RequestTimeoutSeconds { get; set; }
        public int MaxPackagesPerRequest { get; set; } = 15;
        public int MaxRetryCount { get; set; } = 2;
        public int RetryDelayMilliseconds { get; set; } = 2000;
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
