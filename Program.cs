using System.Collections.Concurrent;
using System.Diagnostics;
using System.Globalization;
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
    private const string CheckpointSchemaVersion = "2026-06-26-version-range-v2";
    private const int ProjectMaxDegreeOfParallelism = 4;
    private const int GeminiGlobalConcurrencyLimit = 4;

    private static readonly object ConsoleLock = new();
    private static readonly SemaphoreSlim GeminiRequestGate = new(GeminiGlobalConcurrencyLimit, GeminiGlobalConcurrencyLimit);
    private static readonly ConcurrentBag<GeminiApiDiagnostic> GeminiApiDiagnostics = new();
    private static readonly ConcurrentQueue<ConsoleLogEntry> ConsoleLogEntries = new();
    private static long ConsoleLogSequence;

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
        InstallConsoleCapture();
        var totalStopwatch = Stopwatch.StartNew();

        try
        {
            var geminiSettings = GetGeminiSettings();
            var apiKey = GetGeminiApiKey(geminiSettings);
            var configuredModelName = GetGeminiModelName(geminiSettings);
            var modelName = await ResolveUsableGeminiModelNameAsync(apiKey, configuredModelName, geminiSettings);
            var rootFolder = PromptForAuditFolder();
            var csprojFiles = FindCsprojFiles(rootFolder);

            if (csprojFiles.Count == 0)
            {
                WriteLine($"No .csproj files were found under: {rootFolder}");
                return 0;
            }

            var auditResultsDirectory = Path.Combine(GetApplicationRootDirectory(), "audit-results");
            var runFolderName = DateTime.Now.ToString("yyyyMMdd HH-mm-ss", CultureInfo.InvariantCulture);
            var outputDirectory = ResolveRunOutputDirectory(auditResultsDirectory, runFolderName, csprojFiles, modelName);

            WriteLine($"Audit root folder: {rootFolder}");
            WriteLine($"Found {csprojFiles.Count} .csproj file(s).");
            WriteLine($"Using Gemini model: {modelName}");
            WriteLine($"Run output directory: {outputDirectory}");
            var runTimestamp = DateTime.UtcNow.ToString("yyyyMMdd-HHmmssfff");
            var artifactSet = CreateArtifactSet(outputDirectory, runTimestamp);
            var checkpointDirectory = Path.Combine(outputDirectory, "checkpoints");
            Directory.CreateDirectory(checkpointDirectory);

            var completedCheckpointResults = LoadCheckpointResults(checkpointDirectory, csprojFiles, modelName);
            var completedProjectPaths = completedCheckpointResults
                .Where(IsProjectFullySuccessfulForResume)
                .Select(x => Path.GetFullPath(x.ProjectPath))
                .ToHashSet(StringComparer.OrdinalIgnoreCase);
            var pendingCsprojFiles = csprojFiles
                .Where(path => !completedProjectPaths.Contains(Path.GetFullPath(path)))
                .ToList();

            WriteLine($"Max concurrent project processing: {ProjectMaxDegreeOfParallelism}");
            WriteLine($"Global Gemini request concurrency: {GeminiGlobalConcurrencyLimit}");
            WriteLine($"Checkpoint directory: {checkpointDirectory}");
            WriteLine($"Existing checkpoint(s) loaded for resume: {completedCheckpointResults.Count}.");
            WriteLine($"Pending .csproj file(s) to process in this run: {pendingCsprojFiles.Count}.");
            WriteLine("Starting parallel checkpointed evaluation: RAG-LLM, Zero-Shot, and CodeBERT dataset export.");

            var resultsByProjectPath = new ConcurrentDictionary<string, ProjectAuditResult>(StringComparer.OrdinalIgnoreCase);
            foreach (var checkpointResult in completedCheckpointResults)
            {
                resultsByProjectPath[Path.GetFullPath(checkpointResult.ProjectPath)] = checkpointResult;
            }

            var artifactWriteLock = new SemaphoreSlim(1, 1);
            async Task SaveAggregateArtifactsAsync(CancellationToken cancellationToken)
            {
                await artifactWriteLock.WaitAsync(cancellationToken);
                try
                {
                    try
                    {
                        SaveFinalAuditArtifacts(
                            artifactSet,
                            rootFolder,
                            modelName,
                            resultsByProjectPath.Values
                                .OrderBy(x => x.ProjectPath, StringComparer.OrdinalIgnoreCase)
                                .ToList());
                    }
                    catch (Exception ex)
                    {
                        WriteError($"[Artifacts] Interim aggregate save failed and will be retried later: {ex.Message}");
                    }
                }
                finally
                {
                    artifactWriteLock.Release();
                }
            }

            await SaveAggregateArtifactsAsync(CancellationToken.None);

            var processedCount = 0;
            await Parallel.ForEachAsync(
                pendingCsprojFiles,
                new ParallelOptions
                {
                    MaxDegreeOfParallelism = ProjectMaxDegreeOfParallelism,
                    CancellationToken = CancellationToken.None
                },
                async (csprojPath, cancellationToken) =>
                {
                    var projectNumber = Interlocked.Increment(ref processedCount);
                    var checkpointPath = CreateProjectCheckpointPath(checkpointDirectory, BuildProjectKey(csprojPath));

                    if (File.Exists(checkpointPath) &&
                        TryLoadCheckpointResult(checkpointPath, csprojFiles, modelName, out var existingResult) &&
                        IsProjectFullySuccessfulForResume(existingResult))
                    {
                        resultsByProjectPath[Path.GetFullPath(existingResult.ProjectPath)] = existingResult;
                        WriteLine($"[Checkpoint] Skipping existing project result {projectNumber}/{pendingCsprojFiles.Count}: {existingResult.ProjectPath}");
                        await SaveAggregateArtifactsAsync(cancellationToken);
                        return;
                    }

                    if (File.Exists(checkpointPath))
                    {
                        WriteLine($"[Checkpoint] Existing checkpoint is incomplete/API_FAILED and will be retried: {csprojPath}");
                    }

                    WriteLine($"Processing project {projectNumber}/{pendingCsprojFiles.Count}: {csprojPath}");

                    var result = await ProcessProjectAsync(
                        csprojPath,
                        apiKey,
                        modelName,
                        geminiSettings,
                        outputDirectory,
                        cancellationToken);

                    SaveProjectCheckpoint(checkpointDirectory, result);
                    resultsByProjectPath[Path.GetFullPath(result.ProjectPath)] = result;
                    await SaveAggregateArtifactsAsync(cancellationToken);
                    WriteLine($"Checkpoint and aggregate reports saved after project: {result.ProjectKey}");
                });

            var results = resultsByProjectPath.Values
                .OrderBy(x => x.ProjectPath, StringComparer.OrdinalIgnoreCase)
                .ToList();

            var missingCheckpointResults = LoadCheckpointResults(checkpointDirectory, csprojFiles, modelName)
                .Where(x => !resultsByProjectPath.ContainsKey(Path.GetFullPath(x.ProjectPath)))
                .ToList();

            foreach (var missingResult in missingCheckpointResults)
            {
                resultsByProjectPath[Path.GetFullPath(missingResult.ProjectPath)] = missingResult;
            }

            results = resultsByProjectPath.Values
                .OrderBy(x => x.ProjectPath, StringComparer.OrdinalIgnoreCase)
                .ToList();
            SaveFinalAuditArtifacts(artifactSet, rootFolder, modelName, results);

            totalStopwatch.Stop();
            WriteLine("Batch audit completed.");
            WriteLine($"Succeeded projects: {results.Count(IsProjectFullySuccessfulForResume)}.");
            WriteLine($"Incomplete/API_FAILED projects: {results.Count(x => !IsProjectFullySuccessfulForResume(x))}.");
            WriteLine($"Total elapsed time: {FormatElapsed(totalStopwatch.Elapsed)}.");
            WriteLine($"RAG-LLM JSON report: {artifactSet.RagJsonPath}");
            WriteLine($"Zero-Shot JSON report: {artifactSet.ZeroShotJsonPath}");
            WriteLine($"CodeBERT JSON report: {artifactSet.CodeBertJsonPath}");
            WriteLine($"Comprehensive Excel report: {artifactSet.ExcelReportPath}");
            WriteLine($"Interactive HTML report: {artifactSet.HtmlReportPath}");
            WriteLine($"Gemini API diagnostics JSON: {artifactSet.ApiDiagnosticsJsonPath}");
            WriteLine($"Console execution log JSON: {artifactSet.ConsoleLogJsonPath}");
            SaveConsoleLogJson(artifactSet.ConsoleLogJsonPath);

            return results.Any(x => !IsProjectFullySuccessfulForResume(x)) ? 2 : 0;
        }
        catch (GeminiConfigurationException ex)
        {
            WriteError($"Gemini configuration error: {ex.Message}");
            return 1;
        }
        catch (Exception ex)
        {
            WriteError($"Batch audit failed: {ex.Message}");
            return 1;
        }
    }

    public static Task<GeminiResponse?> AnalyzeWithGemini(
        IReadOnlyCollection<NuGetPackageReference> packageReferences,
        string securityContext)
    {
        var geminiSettings = GetGeminiSettings();
        var scenario = string.IsNullOrWhiteSpace(securityContext) || securityContext.Trim() == "[]"
            ? AuditScenario.ZeroShot
            : AuditScenario.RagLlm;
        var apiKey = GetGeminiApiKey(geminiSettings);
        var modelName = ResolveUsableGeminiModelNameAsync(apiKey, GetGeminiModelName(geminiSettings), geminiSettings)
            .GetAwaiter()
            .GetResult();

        return AnalyzeWithGeminiWithBatching(
            apiKey,
            modelName,
            packageReferences,
            securityContext,
            geminiSettings,
            scenario,
            CancellationToken.None);
    }

    public static string GetGeminiApiKey()
    {
        return GetGeminiApiKey(GetGeminiSettings());
    }

    public static string GetGeminiModelName()
    {
        return GetGeminiModelName(GetGeminiSettings());
    }

    private static async Task<string> ResolveUsableGeminiModelNameAsync(
        string apiKey,
        string configuredModelName,
        GeminiSettings settings)
    {
        var configured = NormalizeModelName(configuredModelName);
        var generateCapableModels = await TryListGeminiGenerateContentModelsAsync(apiKey, settings);

        if (generateCapableModels.Count == 0)
        {
            WriteLine($"[Gemini] Could not list available models. Using configured model: {configured}");
            return configured;
        }

        if (generateCapableModels.Contains(configured))
        {
            return configured;
        }

        var preferredModels = new[]
        {
            "gemini-2.5-pro",
            "gemini-3.5-flash",
            "gemini-2.5-flash",
            "gemini-2.0-flash",
            "gemini-flash-latest",
            "gemini-pro-latest"
        };

        var selected = preferredModels.FirstOrDefault(generateCapableModels.Contains)
            ?? generateCapableModels.First();

        WriteLine($"[Gemini] Configured model '{configured}' is not available for generateContent. Using '{selected}' instead.");
        return selected;
    }

    private static async Task<HashSet<string>> TryListGeminiGenerateContentModelsAsync(
        string apiKey,
        GeminiSettings settings)
    {
        var result = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        try
        {
            using var httpClient = new HttpClient
            {
                Timeout = TimeSpan.FromSeconds(Math.Max(10, settings.RequestTimeoutSeconds))
            };
            httpClient.DefaultRequestHeaders.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
            httpClient.DefaultRequestHeaders.Add("X-Goog-Api-Key", apiKey);

            var modelsEndpoint = BuildGeminiModelsEndpoint(settings.GenerateContentEndpointTemplate);
            using var response = await httpClient.GetAsync(modelsEndpoint);
            var responseContent = await response.Content.ReadAsStringAsync();
            AddGeminiApiDiagnostic(new GeminiApiDiagnostic
            {
                TimestampUtc = DateTimeOffset.UtcNow,
                Operation = "ListModels",
                Endpoint = modelsEndpoint,
                ModelName = string.Empty,
                Scenario = string.Empty,
                PackageCount = 0,
                HttpStatusCode = (int)response.StatusCode,
                HttpStatusDescription = response.StatusCode.ToString(),
                Success = response.IsSuccessStatusCode,
                ResponseHeaders = CollectHeaders(response),
                RateLimitHeaders = CollectRateLimitHeaders(response),
                ResponsePreview = TruncateForDisplay(responseContent, 1000)
            });

            if (!response.IsSuccessStatusCode)
            {
                WriteLine($"[Gemini] ListModels failed: HTTP {(int)response.StatusCode} ({response.StatusCode}).");
                return result;
            }

            var payload = JsonSerializer.Deserialize<GeminiModelListResponse>(responseContent, SerializerOptions);

            foreach (var model in payload?.Models ?? new List<GeminiModelMetadata>())
            {
                if (model.SupportedGenerationMethods.Any(x => string.Equals(x, "generateContent", StringComparison.OrdinalIgnoreCase)))
                {
                    var normalized = NormalizeModelName(model.Name);
                    if (!string.IsNullOrWhiteSpace(normalized))
                    {
                        result.Add(normalized);
                    }
                }
            }

            WriteLine($"[Gemini] generateContent-capable models discovered: {result.Count}.");
        }
        catch (Exception ex)
        {
            AddGeminiApiDiagnostic(new GeminiApiDiagnostic
            {
                TimestampUtc = DateTimeOffset.UtcNow,
                Operation = "ListModels",
                Endpoint = BuildGeminiModelsEndpoint(settings.GenerateContentEndpointTemplate),
                Success = false,
                ErrorMessage = ex.Message
            });
            WriteLine($"[Gemini] ListModels skipped because it failed: {ex.Message}");
        }

        return result;
    }

    private static string BuildGeminiModelsEndpoint(string generateContentEndpointTemplate)
    {
        var marker = "/models/{0}:generateContent";
        var markerIndex = generateContentEndpointTemplate.IndexOf(marker, StringComparison.OrdinalIgnoreCase);

        if (markerIndex > 0)
        {
            return generateContentEndpointTemplate[..markerIndex] + "/models";
        }

        return "https://generativelanguage.googleapis.com/v1/models";
    }

    private static string NormalizeModelName(string modelName)
    {
        if (string.IsNullOrWhiteSpace(modelName))
        {
            return string.Empty;
        }

        var trimmed = modelName.Trim();
        return trimmed.StartsWith("models/", StringComparison.OrdinalIgnoreCase)
            ? trimmed["models/".Length..]
            : trimmed;
    }

    private static async Task<ProjectAuditResult> ProcessProjectAsync(
        string csprojPath,
        string apiKey,
        string modelName,
        GeminiSettings geminiSettings,
        string outputDirectory,
        CancellationToken cancellationToken)
    {
        var stopwatch = Stopwatch.StartNew();
        var projectName = Path.GetFileNameWithoutExtension(csprojPath);
        var projectKey = BuildProjectKey(csprojPath);
        var result = new ProjectAuditResult
        {
            ProjectName = projectName,
            ProjectKey = projectKey,
            ProjectPath = csprojPath,
            ModelName = modelName,
            CheckpointSchemaVersion = CheckpointSchemaVersion,
            StartedAtUtc = DateTimeOffset.UtcNow
        };

        try
        {
            WriteLine($"[{projectKey}] Extracting packages...");
            var packageReferences = CsprojPackageExtractor.ExtractPackageReferences(csprojPath);
            result.PackageCount = packageReferences.Count;
            result.ExtractedPackages = packageReferences.ToList();

            if (packageReferences.Count == 0)
            {
                result.Success = true;
                result.Messages.Add("No PackageReference entries were found. Project skipped.");
                WriteLine($"[{projectKey}] No PackageReference entries were found. Skipping scenarios.");
                return result;
            }

            WriteLine($"[{projectKey}] Found {packageReferences.Count} package(s). Starting Zero-Shot and retrieval concurrently.");

            var zeroShotTask = RunGeminiScenarioSafelyAsync(
                projectKey,
                AuditScenario.ZeroShot,
                apiKey,
                modelName,
                geminiSettings,
                packageReferences,
                "[]",
                cancellationToken);

            var securityContextTask = SecurityReferenceProvider.GetSecurityContextWithDiagnosticsAsync(
                packageReferences.Select(x => x.PackageName).ToList(),
                cancellationToken);
            var securityContextResult = await securityContextTask;
            result.SecurityReferenceSource = securityContextResult.Source;
            result.RetrievalDiagnostics.AddRange(securityContextResult.Diagnostics);

            foreach (var diagnostic in securityContextResult.Diagnostics)
            {
                WriteLine($"[{projectKey}] [Retrieval] {diagnostic}");
            }

            var securityContext = securityContextResult.Context;
            var groundTruthLabels = GroundTruthProvider.BuildLabels(packageReferences, securityContext);
            result.GroundTruthLabels = groundTruthLabels.ToList();

            WriteLine($"[{projectKey}] Ground truth prepared. Starting RAG-LLM and CodeBERT dataset preparation concurrently.");

            var ragTask = RunGeminiScenarioSafelyAsync(
                projectKey,
                AuditScenario.RagLlm,
                apiKey,
                modelName,
                geminiSettings,
                packageReferences,
                securityContext,
                cancellationToken);

            var codeBertTask = Task.Run(
                () => CodeBertDatasetExporter.BuildDatasetRecords(packageReferences, groundTruthLabels),
                cancellationToken);

            var zeroShotResult = await zeroShotTask;
            var ragResult = await ragTask;
            result.Scenarios.Add(zeroShotResult);
            result.Scenarios.Add(ragResult);

            foreach (var scenarioResult in result.Scenarios)
            {
                if (scenarioResult.Response is null)
                {
                    scenarioResult.Status = "API_FAILED";
                    scenarioResult.ExcludedFromMetrics = true;
                    scenarioResult.MetricExclusionReason = "Prediksi LLM tidak tersedia karena API gagal setelah retry. Skenario ini tidak dimasukkan ke confusion matrix untuk menjaga integritas evaluasi.";
                    result.Messages.Add($"{scenarioResult.Scenario} marked API_FAILED and excluded from metrics. {scenarioResult.ErrorMessage}");
                    continue;
                }

                var metrics = ModelEvaluator.Calculate(
                    $"{projectKey}:{GetScenarioDisplayName(scenarioResult.Scenario)}",
                    scenarioResult.Response.VulnerabilityReports,
                    groundTruthLabels);

                scenarioResult.Metrics = metrics;
            }

            try
            {
                result.CodeBertRecords = await codeBertTask;
                result.Messages.Add($"CodeBERT records prepared: {result.CodeBertRecords.Count}.");
            }
            catch (Exception ex)
            {
                result.Messages.Add($"CodeBERT dataset preparation failed: {ex.Message}");
            }

            result.Success = IsProjectFullySuccessfulForResume(result);
            return result;
        }
        catch (Exception ex)
        {
            result.Success = false;
            result.ErrorMessage = ex.Message;
            WriteError($"[{projectKey}] Project failed: {ex.Message}");
            return result;
        }
        finally
        {
            stopwatch.Stop();
            result.CompletedAtUtc = DateTimeOffset.UtcNow;
            result.ElapsedSeconds = stopwatch.Elapsed.TotalSeconds;
            WriteLine($"[{projectKey}] Completed in {FormatElapsed(stopwatch.Elapsed)}.");
        }
    }

    private static async Task<ScenarioAuditResult> RunGeminiScenarioSafelyAsync(
        string projectKey,
        AuditScenario scenario,
        string apiKey,
        string modelName,
        GeminiSettings settings,
        IReadOnlyCollection<NuGetPackageReference> packageReferences,
        string securityContext,
        CancellationToken cancellationToken)
    {
        var stopwatch = Stopwatch.StartNew();
        var result = new ScenarioAuditResult
        {
            Scenario = scenario,
            StartedAtUtc = DateTimeOffset.UtcNow
        };

        try
        {
            WriteLine($"[{projectKey}] [{GetScenarioDisplayName(scenario)}] Starting Gemini inference.");
            var response = await AnalyzeWithGeminiWithBatching(
                apiKey,
                modelName,
                packageReferences,
                securityContext,
                settings,
                scenario,
                cancellationToken);

            if (response is null)
            {
                throw new GeminiApiFailedException("Gemini tidak mengembalikan payload prediksi setelah seluruh retry selesai.");
            }

            result.Response = NormalizeResponse(packageReferences, response);
            result.Status = "SUCCESS";
            result.ExcludedFromMetrics = false;
            result.Success = true;
            result.VulnerableCount = result.Response.VulnerabilityReports.Count(x => x.IsVulnerable);
            WriteLine($"[{projectKey}] [{GetScenarioDisplayName(scenario)}] Finished. Vulnerable detections: {result.VulnerableCount}.");
        }
        catch (Exception ex)
        {
            result.Success = false;
            result.Status = "API_FAILED";
            result.ExcludedFromMetrics = true;
            result.MetricExclusionReason = "Prediksi LLM tidak tersedia karena API gagal setelah retry. Tidak ada fallback ke Ground Truth.";
            result.ErrorMessage = ex.Message;
            WriteError($"[{projectKey}] [{GetScenarioDisplayName(scenario)}] Failed: {ex.Message}");
        }
        finally
        {
            stopwatch.Stop();
            result.CompletedAtUtc = DateTimeOffset.UtcNow;
            result.ElapsedSeconds = stopwatch.Elapsed.TotalSeconds;
        }

        return result;
    }

    private static async Task<GeminiResponse?> AnalyzeWithGeminiWithBatching(
        string apiKey,
        string modelName,
        IReadOnlyCollection<NuGetPackageReference> packageReferences,
        string securityContext,
        GeminiSettings settings,
        AuditScenario scenario,
        CancellationToken cancellationToken)
    {
        if (packageReferences.Count <= settings.MaxPackagesPerRequest)
        {
            var scopedSecurityContext = scenario == AuditScenario.RagLlm
                ? FilterSecurityContextForPackages(securityContext, packageReferences.Select(x => x.PackageName))
                : "[]";

            return await AnalyzeWithGeminiWithRetry(
                apiKey,
                modelName,
                packageReferences,
                scopedSecurityContext,
                settings,
                scenario,
                cancellationToken);
        }

        var batches = packageReferences.Chunk(settings.MaxPackagesPerRequest).ToList();
        var mergedReports = new List<VulnerabilityReport>();

        for (var i = 0; i < batches.Count; i++)
        {
            cancellationToken.ThrowIfCancellationRequested();

            var batch = batches[i];
            var scopedSecurityContext = scenario == AuditScenario.RagLlm
                ? FilterSecurityContextForPackages(securityContext, batch.Select(x => x.PackageName))
                : "[]";

            WriteLine($"[Gemini] {GetScenarioDisplayName(scenario)} batch {i + 1}/{batches.Count}, packages={batch.Length}.");
            var batchResponse = await AnalyzeWithGeminiWithRetry(
                apiKey,
                modelName,
                batch,
                scopedSecurityContext,
                settings,
                scenario,
                cancellationToken);

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
        GeminiSettings settings,
        AuditScenario scenario,
        CancellationToken cancellationToken)
    {
        var maxAttempts = settings.MaxRetryCount + 1;

        for (var attempt = 1; attempt <= maxAttempts; attempt++)
        {
            try
            {
                var response = await AnalyzeWithGemini(
                    apiKey,
                    modelName,
                    packageReferences,
                    securityContext,
                    settings,
                    scenario,
                    cancellationToken);

                if (response is not null)
                {
                    return response;
                }

                if (attempt < maxAttempts)
                {
                    var delay = CalculateBackoffDelay(settings.RetryDelayMilliseconds, attempt);
                    WriteLine($"[Gemini] Empty response attempt {attempt}/{maxAttempts}. Retrying in {delay.TotalMilliseconds:0}ms.");
                    await Task.Delay(delay, cancellationToken);
                }
            }
            catch (TimeoutException ex) when (attempt < maxAttempts)
            {
                var delay = CalculateBackoffDelay(settings.RetryDelayMilliseconds, attempt);
                WriteLine($"[Gemini] Timeout attempt {attempt}/{maxAttempts}: {ex.Message}. Retrying in {delay.TotalMilliseconds:0}ms.");
                await Task.Delay(delay, cancellationToken);
            }
            catch (HttpRequestException ex) when (attempt < maxAttempts && IsTransientStatusCode(ex.StatusCode))
            {
                var delay = CalculateBackoffDelay(settings.RetryDelayMilliseconds, attempt);
                WriteLine($"[Gemini] Transient HTTP attempt {attempt}/{maxAttempts}: {ex.StatusCode}. Retrying in {delay.TotalMilliseconds:0}ms.");
                await Task.Delay(delay, cancellationToken);
            }
            catch (JsonException ex) when (attempt < maxAttempts)
            {
                var delay = CalculateBackoffDelay(settings.RetryDelayMilliseconds, attempt);
                WriteLine($"[Gemini] Invalid JSON attempt {attempt}/{maxAttempts}: {ex.Message}. Retrying in {delay.TotalMilliseconds:0}ms.");
                await Task.Delay(delay, cancellationToken);
            }
        }

        throw new GeminiApiFailedException($"Gemini API failed after {maxAttempts} attempt(s). No prediction was produced.");
    }

    private static async Task<GeminiResponse?> AnalyzeWithGemini(
        string apiKey,
        string modelName,
        IReadOnlyCollection<NuGetPackageReference> packageReferences,
        string securityContext,
        GeminiSettings settings,
        AuditScenario scenario,
        CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(apiKey);
        ArgumentException.ThrowIfNullOrWhiteSpace(modelName);
        ArgumentNullException.ThrowIfNull(packageReferences);
        ArgumentException.ThrowIfNullOrWhiteSpace(securityContext);
        ArgumentNullException.ThrowIfNull(settings);

        var packageText = BuildPackagePrompt(packageReferences);
        ArgumentException.ThrowIfNullOrWhiteSpace(packageText);

        await GeminiRequestGate.WaitAsync(cancellationToken);
        var requestStopwatch = Stopwatch.StartNew();
        var endpoint = string.Format(settings.GenerateContentEndpointTemplate, modelName);
        var diagnosticRecorded = false;

        try
        {
            using var httpClient = new HttpClient
            {
                Timeout = TimeSpan.FromSeconds(settings.RequestTimeoutSeconds)
            };
            httpClient.DefaultRequestHeaders.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
            httpClient.DefaultRequestHeaders.Add("X-Goog-Api-Key", apiKey);

            var prompt = BuildGeminiPrompt(packageText, securityContext, scenario);
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
                }
            };

            using var content = new StringContent(JsonSerializer.Serialize(requestBody), Encoding.UTF8, "application/json");
            using var response = await httpClient.PostAsync(endpoint, content, cancellationToken);
            var responseContent = await response.Content.ReadAsStringAsync(cancellationToken);
            requestStopwatch.Stop();
            AddGeminiApiDiagnostic(new GeminiApiDiagnostic
            {
                TimestampUtc = DateTimeOffset.UtcNow,
                Operation = "GenerateContent",
                Endpoint = endpoint,
                ModelName = modelName,
                Scenario = GetScenarioDisplayName(scenario),
                PackageCount = packageReferences.Count,
                HttpStatusCode = (int)response.StatusCode,
                HttpStatusDescription = response.StatusCode.ToString(),
                Success = response.IsSuccessStatusCode,
                ElapsedMilliseconds = requestStopwatch.Elapsed.TotalMilliseconds,
                ResponseHeaders = CollectHeaders(response),
                RateLimitHeaders = CollectRateLimitHeaders(response),
                ResponsePreview = TruncateForDisplay(responseContent, 1000)
            });
            diagnosticRecorded = true;

            if (response.StatusCode is HttpStatusCode.Unauthorized or HttpStatusCode.Forbidden)
            {
                throw new GeminiConfigurationException("API key Gemini tidak valid atau tidak memiliki akses ke model yang dipakai.");
            }

            if (response.StatusCode == HttpStatusCode.NotFound)
            {
                throw new GeminiConfigurationException(
                    $"Model Gemini '{modelName}' tidak ditemukan. Response: {TruncateForDisplay(responseContent)}");
            }

            if (response.StatusCode == HttpStatusCode.TooManyRequests || (int)response.StatusCode >= 500)
            {
                throw new HttpRequestException(
                    $"Gemini transient response: {(int)response.StatusCode} ({response.StatusCode}).",
                    null,
                    response.StatusCode);
            }

            response.EnsureSuccessStatusCode();

            var geminiApiResponse = JsonSerializer.Deserialize<GeminiApiResponse>(responseContent, SerializerOptions);
            var json = geminiApiResponse?.Candidates?.FirstOrDefault()?.Content?.Parts?.FirstOrDefault()?.Text;

            if (string.IsNullOrWhiteSpace(json))
            {
                WriteLine("[Gemini] Response payload is empty.");
                return null;
            }

            return JsonSerializer.Deserialize<GeminiResponse>(ExtractJsonPayload(json), SerializerOptions);
        }
        catch (TaskCanceledException ex) when (!cancellationToken.IsCancellationRequested)
        {
            requestStopwatch.Stop();
            AddGeminiApiDiagnostic(new GeminiApiDiagnostic
            {
                TimestampUtc = DateTimeOffset.UtcNow,
                Operation = "GenerateContent",
                Endpoint = endpoint,
                ModelName = modelName,
                Scenario = GetScenarioDisplayName(scenario),
                PackageCount = packageReferences.Count,
                Success = false,
                ElapsedMilliseconds = requestStopwatch.Elapsed.TotalMilliseconds,
                ErrorMessage = ex.Message
            });
            throw new TimeoutException($"Permintaan ke Gemini melebihi batas waktu {settings.RequestTimeoutSeconds:0} detik.", ex);
        }
        catch (Exception ex)
        {
            requestStopwatch.Stop();
            if (!diagnosticRecorded)
            {
                AddGeminiApiDiagnostic(new GeminiApiDiagnostic
                {
                    TimestampUtc = DateTimeOffset.UtcNow,
                    Operation = "GenerateContent",
                    Endpoint = endpoint,
                    ModelName = modelName,
                    Scenario = GetScenarioDisplayName(scenario),
                    PackageCount = packageReferences.Count,
                    Success = false,
                    ElapsedMilliseconds = requestStopwatch.Elapsed.TotalMilliseconds,
                    ErrorMessage = ex.Message
                });
            }
            throw;
        }
        finally
        {
            GeminiRequestGate.Release();
        }
    }

    private static string PromptForAuditFolder()
    {
        while (true)
        {
            Console.Write("Please enter the folder path containing the .csproj files to audit: ");
            var input = Console.ReadLine();
            AddConsoleLog("stdin", input ?? string.Empty, true);
            var folderPath = TrimPathInput(input);

            if (string.IsNullOrWhiteSpace(folderPath))
            {
                WriteLine("Folder path is required.");
                continue;
            }

            var fullPath = Path.GetFullPath(folderPath);
            if (!Directory.Exists(fullPath))
            {
                WriteLine($"Folder does not exist: {fullPath}");
                continue;
            }

            return fullPath;
        }
    }

    private static IReadOnlyList<string> FindCsprojFiles(string rootFolder)
    {
        return Directory.EnumerateFiles(rootFolder, "*.csproj", SearchOption.AllDirectories)
            .Where(path => !IsIgnoredProjectPath(path))
            .OrderBy(path => path, StringComparer.OrdinalIgnoreCase)
            .ToList();
    }

    private static bool IsIgnoredProjectPath(string path)
    {
        var normalized = path.Replace(Path.AltDirectorySeparatorChar, Path.DirectorySeparatorChar);
        return normalized.Contains($"{Path.DirectorySeparatorChar}bin{Path.DirectorySeparatorChar}", StringComparison.OrdinalIgnoreCase) ||
               normalized.Contains($"{Path.DirectorySeparatorChar}obj{Path.DirectorySeparatorChar}", StringComparison.OrdinalIgnoreCase);
    }

    private static string TrimPathInput(string? input)
    {
        return string.IsNullOrWhiteSpace(input)
            ? string.Empty
            : input.Trim().Trim('"');
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

            if (!document.RootElement.TryGetProperty("Gemini", out var geminiSection) ||
                geminiSection.ValueKind != JsonValueKind.Object)
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

        if (string.IsNullOrWhiteSpace(settings.GenerateContentEndpointTemplate) ||
            !settings.GenerateContentEndpointTemplate.Contains("{0}", StringComparison.Ordinal))
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

        try
        {
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
        catch (JsonException)
        {
            return "[]";
        }
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

    private static string BuildPackagePrompt(IEnumerable<NuGetPackageReference> packageReferences)
    {
        var builder = new StringBuilder();

        foreach (var packageReference in packageReferences)
        {
            builder.AppendLine($"- {packageReference.PackageName}: {packageReference.CurrentVersion}");
        }

        return builder.ToString().TrimEnd();
    }

    private static string BuildGeminiPrompt(string packageText, string securityContext, AuditScenario scenario)
    {
        var jsonContract = """
Return ONLY valid JSON.
Do not return markdown.
Do not return code fences.
Do not return explanations outside JSON.
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

JSON rules:
- Always return one JSON object.
- Always include the VulnerabilityReports array.
- Return exactly one item per package.
- Use the package name and version exactly as provided.
- Use empty string for unknown CVE_ID and other unknown string values.
- Always fill bilingual fields: English and Indonesian versions for Severity, MitigationPlan, and ReasoningTrace.
- Severity must use English values Critical, High, Moderate, Low, or Unknown.
- SeverityIndonesia must use Kritis, Tinggi, Sedang, Rendah, or Tidak diketahui.
""";

        if (scenario == AuditScenario.ZeroShot)
        {
            return $$"""
You are a NuGet security auditor evaluating the Zero-Shot baseline scenario for a controlled experiment.
Do not use external reference facts, advisory snippets, retrieved context, URLs, or browsing.
Classify only from the package name/version patterns and your pretrained knowledge.
Set IsGroundedInReference to false for every item because no retrieval context is provided.
If you are uncertain, prefer IsVulnerable=false and explain the uncertainty in both reasoning fields.

{{jsonContract}}

Local packages:
{{packageText}}
""";
        }

        return $$"""
You are a NuGet security auditor evaluating the RAG-LLM scenario for a controlled experiment.
Use the provided security reference data as ground-truth context from GitHub Advisory/local DB.
Only mark IsVulnerable=true when the package is supported by the provided reference context.
Set IsGroundedInReference=true only when the finding is directly supported by the reference context.
If a package is absent from the reference context, set IsVulnerable=false, IsGroundedInReference=false, Severity=Unknown, and SeverityIndonesia=Tidak diketahui.
Provide mitigation based on the patched version or advisory context when available.

{{jsonContract}}

Local packages:
{{packageText}}

Security reference data:
{{securityContext}}
""";
    }

    private static GeminiResponse NormalizeResponse(
        IReadOnlyCollection<NuGetPackageReference> packageReferences,
        GeminiResponse? geminiResponse)
    {
        var reportLookup = (geminiResponse?.VulnerabilityReports ?? new List<VulnerabilityReport>())
            .Where(x => !string.IsNullOrWhiteSpace(x.PackageName))
            .GroupBy(x => x.PackageName, StringComparer.OrdinalIgnoreCase)
            .ToDictionary(x => x.Key, x => x.First(), StringComparer.OrdinalIgnoreCase);

        var normalizedReports = packageReferences.Select(packageReference =>
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
                Severity = "Unknown",
                SeverityIndonesia = "Tidak diketahui",
                MitigationPlan = string.Empty,
                MitigationPlanIndonesia = string.Empty,
                IsGroundedInReference = false,
                ReasoningTrace = string.Empty,
                ReasoningTraceIndonesia = string.Empty
            };
        }).ToList();

        return new GeminiResponse
        {
            VulnerabilityReports = normalizedReports
        };
    }

    private static string SaveAuditResult(
        string outputDirectory,
        string csprojPath,
        string modelName,
        IReadOnlyCollection<NuGetPackageReference> packageReferences,
        GeminiResponse geminiResponse,
        AuditScenario scenario,
        string projectKey)
    {
        Directory.CreateDirectory(outputDirectory);

        var outputFilePath = Path.Combine(
            outputDirectory,
            $"audit-{projectKey}-{GetScenarioTag(scenario)}-{DateTime.UtcNow:yyyyMMdd-HHmmssfff}.json");

        var sessionRecord = new AuditSessionRecord
        {
            GeneratedAtUtc = DateTimeOffset.UtcNow,
            SourceProjectPath = csprojPath,
            ModelName = modelName,
            Scenario = scenario,
            ExtractedPackages = packageReferences.ToList(),
            VulnerabilityReports = geminiResponse.VulnerabilityReports,
            VulnerabilityReportFieldDescriptions = GetVulnerabilityReportFieldDescriptions()
        };

        File.WriteAllText(outputFilePath, JsonSerializer.Serialize(sessionRecord, SerializerOptions), Encoding.UTF8);
        return outputFilePath;
    }

    private static FinalArtifactSet CreateArtifactSet(string outputDirectory, string timestamp)
    {
        Directory.CreateDirectory(outputDirectory);
        return new FinalArtifactSet
        {
            RagJsonPath = Path.Combine(outputDirectory, $"audit-rag-llm-{timestamp}.json"),
            ZeroShotJsonPath = Path.Combine(outputDirectory, $"audit-zero-shot-{timestamp}.json"),
            CodeBertJsonPath = Path.Combine(outputDirectory, $"audit-codebert-{timestamp}.json"),
            ExcelReportPath = Path.Combine(outputDirectory, $"audit-comprehensive-report-{timestamp}.xlsx"),
            HtmlReportPath = Path.Combine(outputDirectory, $"audit-interactive-report-{timestamp}.html"),
            ApiDiagnosticsJsonPath = Path.Combine(outputDirectory, $"api-diagnostics-{timestamp}.json"),
            ConsoleLogJsonPath = Path.Combine(outputDirectory, $"console-execution-log-{timestamp}.json")
        };
    }

    private static string CreateRunOutputDirectory(string auditResultsDirectory, string runFolderName)
    {
        Directory.CreateDirectory(auditResultsDirectory);

        var outputDirectory = Path.Combine(auditResultsDirectory, runFolderName);
        if (!Directory.Exists(outputDirectory))
        {
            Directory.CreateDirectory(outputDirectory);
            return outputDirectory;
        }

        for (var index = 1; index < 1000; index++)
        {
            var candidateDirectory = Path.Combine(auditResultsDirectory, $"{runFolderName} {index:000}");
            if (!Directory.Exists(candidateDirectory))
            {
                Directory.CreateDirectory(candidateDirectory);
                return candidateDirectory;
            }
        }

        throw new IOException($"Could not create a unique audit result folder for timestamp '{runFolderName}'.");
    }

    private static string ResolveRunOutputDirectory(
        string auditResultsDirectory,
        string runFolderName,
        IReadOnlyCollection<string> csprojFiles,
        string modelName)
    {
        Directory.CreateDirectory(auditResultsDirectory);

        var resumableDirectory = FindLatestCompatibleCheckpointDirectory(auditResultsDirectory, csprojFiles, modelName);
        if (!string.IsNullOrWhiteSpace(resumableDirectory))
        {
            WriteLine($"[Checkpoint] Resuming latest compatible run folder: {resumableDirectory}");
            return resumableDirectory;
        }

        return CreateRunOutputDirectory(auditResultsDirectory, runFolderName);
    }

    private static string? FindLatestCompatibleCheckpointDirectory(
        string auditResultsDirectory,
        IReadOnlyCollection<string> csprojFiles,
        string modelName)
    {
        var allowedProjectPaths = csprojFiles
            .Select(Path.GetFullPath)
            .ToHashSet(StringComparer.OrdinalIgnoreCase);

        return Directory.EnumerateDirectories(auditResultsDirectory)
            .Select(path => new DirectoryInfo(path))
            .OrderByDescending(directory => directory.LastWriteTimeUtc)
            .Select(directory => directory.FullName)
            .FirstOrDefault(directory => HasCompatibleCheckpoint(directory, allowedProjectPaths, modelName));
    }

    private static bool HasCompatibleCheckpoint(
        string outputDirectory,
        HashSet<string> allowedProjectPaths,
        string modelName)
    {
        var checkpointDirectory = Path.Combine(outputDirectory, "checkpoints");
        if (!Directory.Exists(checkpointDirectory))
        {
            return false;
        }

        foreach (var checkpointPath in Directory.EnumerateFiles(checkpointDirectory, "*.json", SearchOption.TopDirectoryOnly))
        {
            try
            {
                var json = File.ReadAllText(checkpointPath, Encoding.UTF8);
                var loadedResult = JsonSerializer.Deserialize<ProjectAuditResult>(json, SerializerOptions);
                if (loadedResult is not null &&
                    !string.IsNullOrWhiteSpace(loadedResult.ProjectPath) &&
                    allowedProjectPaths.Contains(Path.GetFullPath(loadedResult.ProjectPath)) &&
                    IsCheckpointModelCompatible(loadedResult, modelName))
                {
                    return true;
                }
            }
            catch
            {
                // Corrupt checkpoints are ignored; later loading logs the details.
            }
        }

        return false;
    }

    private static void SaveFinalAuditArtifacts(
        FinalArtifactSet artifactSet,
        string rootFolder,
        string modelName,
        IReadOnlyCollection<ProjectAuditResult> results)
    {
        var ragReport = BuildScenarioJsonReport(rootFolder, modelName, AuditScenario.RagLlm, results);
        var zeroShotReport = BuildScenarioJsonReport(rootFolder, modelName, AuditScenario.ZeroShot, results);
        var codeBertReport = BuildCodeBertJsonReport(rootFolder, modelName, results);

        File.WriteAllText(artifactSet.RagJsonPath, JsonSerializer.Serialize(ragReport, SerializerOptions), Encoding.UTF8);
        File.WriteAllText(artifactSet.ZeroShotJsonPath, JsonSerializer.Serialize(zeroShotReport, SerializerOptions), Encoding.UTF8);
        File.WriteAllText(artifactSet.CodeBertJsonPath, JsonSerializer.Serialize(codeBertReport, SerializerOptions), Encoding.UTF8);
        File.WriteAllText(artifactSet.ApiDiagnosticsJsonPath, JsonSerializer.Serialize(BuildApiDiagnosticsReport(rootFolder, modelName), SerializerOptions), Encoding.UTF8);
        SaveComprehensiveExcelReport(artifactSet.ExcelReportPath, rootFolder, modelName, results);
        SaveInteractiveHtmlReport(artifactSet.HtmlReportPath, rootFolder, modelName, results, artifactSet);
    }

    private static IReadOnlyList<ProjectAuditResult> LoadCheckpointResults(
        string checkpointDirectory,
        IReadOnlyCollection<string> csprojFiles,
        string modelName)
    {
        Directory.CreateDirectory(checkpointDirectory);
        var results = new List<ProjectAuditResult>();

        foreach (var checkpointPath in Directory.EnumerateFiles(checkpointDirectory, "*.json", SearchOption.TopDirectoryOnly))
        {
            if (TryLoadCheckpointResult(checkpointPath, csprojFiles, modelName, out var result))
            {
                results.Add(result);
                WriteLine($"[Checkpoint] Loaded compatible checkpoint: {result.ProjectPath}");
            }
        }

        return results
            .GroupBy(x => Path.GetFullPath(x.ProjectPath), StringComparer.OrdinalIgnoreCase)
            .Select(x => x.OrderByDescending(r => r.CompletedAtUtc).First())
            .OrderBy(x => x.ProjectPath, StringComparer.OrdinalIgnoreCase)
            .ToList();
    }

    private static bool TryLoadCheckpointResult(
        string checkpointPath,
        IReadOnlyCollection<string> csprojFiles,
        string modelName,
        out ProjectAuditResult result)
    {
        result = new ProjectAuditResult();

        try
        {
            var allowedProjectPaths = csprojFiles
                .Select(Path.GetFullPath)
                .ToHashSet(StringComparer.OrdinalIgnoreCase);
            var json = File.ReadAllText(checkpointPath, Encoding.UTF8);
            var loadedResult = JsonSerializer.Deserialize<ProjectAuditResult>(json, SerializerOptions);

            if (loadedResult is null ||
                string.IsNullOrWhiteSpace(loadedResult.ProjectPath) ||
                !allowedProjectPaths.Contains(Path.GetFullPath(loadedResult.ProjectPath)) ||
                !IsCheckpointModelCompatible(loadedResult, modelName))
            {
                return false;
            }

            result = loadedResult;
            return true;
        }
        catch (Exception ex)
        {
            WriteLine($"[Checkpoint] Ignoring unreadable checkpoint '{checkpointPath}': {ex.Message}");
            return false;
        }
    }

    private static bool IsCheckpointModelCompatible(ProjectAuditResult result, string modelName)
    {
        return !string.IsNullOrWhiteSpace(result.ModelName) &&
               string.Equals(result.CheckpointSchemaVersion, CheckpointSchemaVersion, StringComparison.OrdinalIgnoreCase) &&
               string.Equals(
                   NormalizeModelName(result.ModelName),
                   NormalizeModelName(modelName),
                   StringComparison.OrdinalIgnoreCase);
    }

    private static void SaveProjectCheckpoint(string checkpointDirectory, ProjectAuditResult result)
    {
        Directory.CreateDirectory(checkpointDirectory);
        var checkpointPath = CreateProjectCheckpointPath(checkpointDirectory, result.ProjectKey);
        var tempCheckpointPath = $"{checkpointPath}.{Guid.NewGuid():N}.tmp";
        File.WriteAllText(tempCheckpointPath, JsonSerializer.Serialize(result, SerializerOptions), Encoding.UTF8);
        File.Move(tempCheckpointPath, checkpointPath, true);
        WriteLine($"[{result.ProjectKey}] Checkpoint saved: {checkpointPath}");
    }

    private static string CreateProjectCheckpointPath(string checkpointDirectory, string projectKey)
    {
        return Path.Combine(checkpointDirectory, $"{SanitizeFileName(projectKey)}.json");
    }

    private static bool IsProjectFullySuccessfulForResume(ProjectAuditResult result)
    {
        var rag = result.Scenarios.FirstOrDefault(x => x.Scenario == AuditScenario.RagLlm);
        var zeroShot = result.Scenarios.FirstOrDefault(x => x.Scenario == AuditScenario.ZeroShot);

        if (result.PackageCount == 0 && result.Success && result.ErrorMessage.Length == 0)
        {
            return true;
        }

        return result.ErrorMessage.Length == 0 &&
               result.PackageCount >= 0 &&
               result.CodeBertRecords.Count > 0 &&
               rag is { Success: true, Response: not null } &&
               zeroShot is { Success: true, Response: not null };
    }

    private static ScenarioJsonReport BuildScenarioJsonReport(
        string rootFolder,
        string modelName,
        AuditScenario scenario,
        IReadOnlyCollection<ProjectAuditResult> results)
    {
        var projectReports = results
            .Select(project => new ProjectScenarioJsonReport
            {
                ProjectName = project.ProjectName,
                ProjectKey = project.ProjectKey,
                ProjectPath = project.ProjectPath,
                PackageCount = project.PackageCount,
                ExtractedPackages = project.ExtractedPackages,
                GroundTruthLabels = project.GroundTruthLabels,
                SecurityReferenceSource = project.SecurityReferenceSource,
                RetrievalDiagnostics = project.RetrievalDiagnostics,
                Scenario = scenario,
                ScenarioResult = project.Scenarios.FirstOrDefault(x => x.Scenario == scenario),
                ScenarioStatus = project.Scenarios.FirstOrDefault(x => x.Scenario == scenario)?.Status ?? "NOT_RUN",
                ExcludedFromMetrics = project.Scenarios.FirstOrDefault(x => x.Scenario == scenario)?.ExcludedFromMetrics ?? true,
                MetricExclusionReason = project.Scenarios.FirstOrDefault(x => x.Scenario == scenario)?.MetricExclusionReason ?? "Scenario was not executed.",
                VulnerabilityReports = project.Scenarios.FirstOrDefault(x => x.Scenario == scenario)?.Response?.VulnerabilityReports ?? new List<VulnerabilityReport>(),
                Metrics = project.Scenarios.FirstOrDefault(x => x.Scenario == scenario)?.Metrics,
                Messages = project.Messages
            })
            .ToList();

        return new ScenarioJsonReport
        {
            GeneratedAtUtc = DateTimeOffset.UtcNow,
            RootFolder = rootFolder,
            ModelName = modelName,
            Scenario = scenario,
            ProjectCount = results.Count,
            SucceededProjectCount = projectReports.Count(x => x.ScenarioResult?.Success == true),
            FailedProjectCount = projectReports.Count(x => x.ScenarioResult?.Success != true),
            TotalExtractedPackages = projectReports.Sum(x => x.ExtractedPackages.Count),
            TotalVulnerabilityReports = projectReports.Sum(x => x.VulnerabilityReports.Count),
            VulnerableFindingCount = projectReports.Sum(x => x.VulnerabilityReports.Count(r => r.IsVulnerable)),
            GroundedFindingCount = projectReports.Sum(x => x.VulnerabilityReports.Count(r => r.IsGroundedInReference)),
            VulnerabilityReportFieldDescriptions = GetVulnerabilityReportFieldDescriptions(),
            MetricFormulaDescriptions = GetMetricFormulaDescriptions(),
            VulnerabilityReports = projectReports
                .SelectMany(project => project.VulnerabilityReports.Select(report => new ProjectVulnerabilityReport
                {
                    ProjectName = project.ProjectName,
                    ProjectKey = project.ProjectKey,
                    ProjectPath = project.ProjectPath,
                    PackageName = report.PackageName,
                    CurrentVersion = report.CurrentVersion,
                    IsVulnerable = report.IsVulnerable,
                    CVE_ID = report.CVE_ID,
                    Severity = report.Severity,
                    SeverityIndonesia = report.SeverityIndonesia,
                    MitigationPlan = report.MitigationPlan,
                    MitigationPlanIndonesia = report.MitigationPlanIndonesia,
                    IsGroundedInReference = report.IsGroundedInReference,
                    ReasoningTrace = report.ReasoningTrace,
                    ReasoningTraceIndonesia = report.ReasoningTraceIndonesia
                }))
                .ToList(),
            Projects = projectReports
        };
    }

    private static ApiDiagnosticsReport BuildApiDiagnosticsReport(string rootFolder, string modelName)
    {
        var diagnostics = GeminiApiDiagnostics
            .OrderBy(x => x.TimestampUtc)
            .ToList();

        return new ApiDiagnosticsReport
        {
            GeneratedAtUtc = DateTimeOffset.UtcNow,
            RootFolder = rootFolder,
            ModelName = modelName,
            TotalCalls = diagnostics.Count,
            SuccessfulCalls = diagnostics.Count(x => x.Success),
            FailedCalls = diagnostics.Count(x => !x.Success),
            RateLimitHeaderObservations = diagnostics
                .Where(x => x.RateLimitHeaders.Count > 0)
                .Select(x => new RateLimitObservation
                {
                    TimestampUtc = x.TimestampUtc,
                    Operation = x.Operation,
                    Scenario = x.Scenario,
                    ModelName = x.ModelName,
                    HttpStatusCode = x.HttpStatusCode,
                    Headers = x.RateLimitHeaders
                })
                .ToList(),
            Diagnostics = diagnostics
        };
    }

    private static CodeBertJsonReport BuildCodeBertJsonReport(
        string rootFolder,
        string modelName,
        IReadOnlyCollection<ProjectAuditResult> results)
    {
        var projectReports = results
            .Select(project => new ProjectCodeBertJsonReport
            {
                ProjectName = project.ProjectName,
                ProjectKey = project.ProjectKey,
                ProjectPath = project.ProjectPath,
                PackageCount = project.PackageCount,
                SecurityReferenceSource = project.SecurityReferenceSource,
                TotalRecords = project.CodeBertRecords.Count,
                TrainingCount = project.CodeBertRecords.Count(x => x.Split == "training"),
                ValidationCount = project.CodeBertRecords.Count(x => x.Split == "validation"),
                TestingCount = project.CodeBertRecords.Count(x => x.Split == "testing"),
                EvaluationStatus = "DATASET_EXPORTED",
                EvaluationNote = "No neural CodeBERT inference was executed in this run; train/import CodeBERT predictions to compute TP/TN/FP/FN.",
                Records = project.CodeBertRecords
            })
            .ToList();

        return new CodeBertJsonReport
        {
            GeneratedAtUtc = DateTimeOffset.UtcNow,
            RootFolder = rootFolder,
            ModelName = modelName,
            ProjectCount = results.Count,
            TotalRecords = projectReports.Sum(x => x.TotalRecords),
            TrainingCount = projectReports.Sum(x => x.TrainingCount),
            ValidationCount = projectReports.Sum(x => x.ValidationCount),
            TestingCount = projectReports.Sum(x => x.TestingCount),
            SplitStrategy = "70% training, 15% validation, 15% testing. For very small datasets, each split is preserved when possible.",
            AugmentationStrategy = "original, semantic_version_normalization, and safe_dummy_dependency records generated from parsed NuGet dependencies and ground-truth labels.",
            EvaluationStatus = "DATASET_EXPORTED",
            EvaluationNote = "This artifact is a labeled dataset baseline. It is ready for CodeBERT training/inference, but it is not itself a neural model prediction result.",
            DatasetFieldDescriptions = GetCodeBertDatasetFieldDescriptions(),
            Projects = projectReports
        };
    }

    private static void SaveComprehensiveExcelReport(
        string outputFilePath,
        string rootFolder,
        string modelName,
        IReadOnlyCollection<ProjectAuditResult> results)
    {
        using var workbook = new XLWorkbook();
        WriteReadMeSheet(workbook);
        WriteRunSummarySheet(workbook, rootFolder, modelName, results);
        WriteModelComparisonSheet(workbook, results);
        WriteMethodComparisonSheet(workbook, results);
        WriteProjectStatusSheet(workbook, results);
        WriteScenarioMetricsSheet(workbook, results);
        WriteFindingDetailSheet(workbook, results);
        WriteFalseReviewSheet(workbook, results, "False Positive Review", "False Positive");
        WriteFalseReviewSheet(workbook, results, "False Negative Review", "False Negative");
        WriteGroundTruthSheet(workbook, results);
        WriteCodeBertSheet(workbook, results);
        WriteCodeBertEvaluationSheet(workbook, results);
        WriteRetrievalDiagnosticsSheet(workbook, results);
        WriteFieldDescriptionsSheet(workbook);
        WriteMetricDefinitionsSheet(workbook);
        workbook.SaveAs(outputFilePath);
    }

    private static void WriteRunSummarySheet(
        XLWorkbook workbook,
        string rootFolder,
        string modelName,
        IReadOnlyCollection<ProjectAuditResult> results)
    {
        var sheet = workbook.Worksheets.Add("Run Summary");
        var metrics = results.SelectMany(x => x.Scenarios).Select(x => x.Metrics).Where(x => x is not null).Cast<EvaluationMetrics>().ToList();

        var rows = new List<(string Metric, string Value)>
        {
            ("GeneratedAtUtc", DateTimeOffset.UtcNow.ToString("O")),
            ("RootFolder", rootFolder),
            ("GeminiModel", modelName),
            ("ExecutionMode", "Parallel checkpointed interactive directory scan"),
            ("MaxDegreeOfParallelism", ProjectMaxDegreeOfParallelism.ToString()),
            ("GlobalGeminiRequestConcurrency", GeminiGlobalConcurrencyLimit.ToString()),
            ("ProjectCount", results.Count.ToString()),
            ("FullySuccessfulProjects", results.Count(IsProjectFullySuccessfulForResume).ToString()),
            ("IncompleteOrApiFailedProjects", results.Count(x => !IsProjectFullySuccessfulForResume(x)).ToString()),
            ("RagLlmProjectResults", results.Count(x => x.Scenarios.Any(s => s.Scenario == AuditScenario.RagLlm && s.Success)).ToString()),
            ("ZeroShotProjectResults", results.Count(x => x.Scenarios.Any(s => s.Scenario == AuditScenario.ZeroShot && s.Success)).ToString()),
            ("CodeBertProjectResults", results.Count(x => x.CodeBertRecords.Count > 0 || x.PackageCount == 0).ToString()),
            ("ApiFailedScenarioResults", results.SelectMany(x => x.Scenarios).Count(s => s.Status == "API_FAILED").ToString()),
            ("MetricExclusionPolicy", "Scenario with API_FAILED or missing LLM prediction is excluded from confusion matrix; no Ground Truth fallback is used."),
            ("GroundTruthPolicy", "A package is labeled vulnerable only when its current version satisfies the advisory vulnerable version range."),
            ("CodeBertRecords", results.Sum(x => x.CodeBertRecords.Count).ToString()),
            ("CodeBertEvaluationPolicy", "CodeBERT dataset rows are exported in this run. CodeBERT prediction metrics require a trained model or imported prediction file."),
            ("MetricRows", metrics.Count.ToString())
        };

        sheet.Cell(1, 1).Value = "Metric";
        sheet.Cell(1, 2).Value = "Value";

        for (var i = 0; i < rows.Count; i++)
        {
            sheet.Cell(i + 2, 1).Value = rows[i].Metric;
            sheet.Cell(i + 2, 2).Value = rows[i].Value;
        }

        FormatUsedRangeAsTable(sheet, 2);
    }

    private static void WriteModelComparisonSheet(XLWorkbook workbook, IReadOnlyCollection<ProjectAuditResult> results)
    {
        var sheet = workbook.Worksheets.Add("Model Comparison");
        var headers = new[] { "Metric", "RAG-LLM", "Zero-Shot", "Delta (RAG-ZeroShot)", "Description" };
        WriteHeaders(sheet, headers);

        var rag = AggregateScenarioMetrics(results, AuditScenario.RagLlm);
        var zeroShot = AggregateScenarioMetrics(results, AuditScenario.ZeroShot);
        var rows = new List<(string Metric, double Rag, double ZeroShot, string Description)>
        {
            ("Accuracy", rag.Accuracy, zeroShot.Accuracy, "Proporsi seluruh prediksi package yang benar."),
            ("Precision", rag.Precision, zeroShot.Precision, "Ketepatan prediksi rentan. Lebih tinggi berarti false positive lebih rendah."),
            ("Recall", rag.Recall, zeroShot.Recall, "Kemampuan menemukan package yang benar-benar rentan."),
            ("F1Score", rag.F1Score, zeroShot.F1Score, "Keseimbangan precision dan recall."),
            ("FalsePositiveRatio", rag.FalsePositiveRatio, zeroShot.FalsePositiveRatio, "Rasio alarm palsu dari seluruh prediksi positif."),
            ("TruePositive", rag.TruePositive, zeroShot.TruePositive, "Jumlah package rentan yang berhasil terdeteksi."),
            ("TrueNegative", rag.TrueNegative, zeroShot.TrueNegative, "Jumlah package aman yang benar terdeteksi aman."),
            ("FalsePositive", rag.FalsePositive, zeroShot.FalsePositive, "Jumlah package aman yang salah ditandai rentan."),
            ("FalseNegative", rag.FalseNegative, zeroShot.FalseNegative, "Jumlah package rentan yang gagal terdeteksi."),
            ("Total", rag.Total, zeroShot.Total, "Total package yang masuk evaluasi.")
        };

        for (var i = 0; i < rows.Count; i++)
        {
            var row = i + 2;
            sheet.Cell(row, 1).Value = rows[i].Metric;
            sheet.Cell(row, 2).Value = rows[i].Rag;
            sheet.Cell(row, 3).Value = rows[i].ZeroShot;
            sheet.Cell(row, 4).Value = rows[i].Rag - rows[i].ZeroShot;
            sheet.Cell(row, 5).Value = rows[i].Description;
        }

        sheet.Range(2, 2, 6, 4).Style.NumberFormat.Format = "0.00%";
        sheet.Column(5).Style.Alignment.WrapText = true;
        FormatUsedRangeAsTable(sheet, headers.Length);
    }

    private static EvaluationMetrics AggregateScenarioMetrics(IReadOnlyCollection<ProjectAuditResult> results, AuditScenario scenario)
    {
        var metrics = results
            .SelectMany(project => project.Scenarios)
            .Where(item => item.Scenario == scenario && item.Metrics is not null)
            .Select(item => item.Metrics!)
            .ToList();

        var truePositive = metrics.Sum(x => x.TruePositive);
        var trueNegative = metrics.Sum(x => x.TrueNegative);
        var falsePositive = metrics.Sum(x => x.FalsePositive);
        var falseNegative = metrics.Sum(x => x.FalseNegative);
        var total = truePositive + trueNegative + falsePositive + falseNegative;
        var precisionDenominator = truePositive + falsePositive;
        var recallDenominator = truePositive + falseNegative;
        var precision = precisionDenominator > 0 ? (double)truePositive / precisionDenominator : 0d;
        var recall = recallDenominator > 0 ? (double)truePositive / recallDenominator : 0d;

        return new EvaluationMetrics
        {
            Scenario = GetScenarioDisplayName(scenario),
            Total = total,
            TruePositive = truePositive,
            TrueNegative = trueNegative,
            FalsePositive = falsePositive,
            FalseNegative = falseNegative,
            Accuracy = total > 0 ? (double)(truePositive + trueNegative) / total : 0d,
            Precision = precision,
            Recall = recall,
            F1Score = precision + recall > 0 ? 2 * precision * recall / (precision + recall) : 0d,
            FalsePositiveRatio = precisionDenominator > 0 ? (double)falsePositive / precisionDenominator : 0d
        };
    }

    private static void WriteReadMeSheet(XLWorkbook workbook)
    {
        var sheet = workbook.Worksheets.Add("README");
        var headers = new[] { "Section", "HowToRead" };
        WriteHeaders(sheet, headers);

        var rows = new List<(string Section, string HowToRead)>
        {
            ("Purpose", "Workbook ini merangkum audit dependency NuGet dari file .csproj. Tiga jalur yang dihasilkan adalah RAG-LLM, Zero-Shot, dan CodeBERT dataset export."),
            ("RAG-LLM", "LLM menerima package list plus security reference hasil retrieval. Gunakan sheet Scenario Metrics dan Finding Detail untuk membaca prediksi dan evaluasinya."),
            ("Zero-Shot", "LLM hanya menerima package list tanpa konteks advisory. Bandingkan dengan RAG-LLM untuk melihat efek retrieval."),
            ("CodeBERT", "Bukan prediksi LLM di workbook ini. Sheet CodeBERT Dataset adalah dataset baseline untuk training/evaluasi model CodeBERT, memakai label ground truth."),
            ("Ground Truth Version Range", "Package hanya dianggap vulnerable jika CurrentVersion masuk VulnerableVersionRange. Ini mencegah package patched tetap dihitung sebagai vulnerable hanya karena namanya punya advisory."),
            ("Run Summary", "Ringkasan eksekusi: model, jumlah project, jumlah sukses/gagal, concurrency, dan jumlah record."),
            ("Method Comparison", "Tabel cepat untuk melihat status tiga metode per project: RAG-LLM, Zero-Shot, dan CodeBERT."),
            ("Project Status", "Status per project, termasuk status RAG, Zero-Shot, jumlah record CodeBERT, dan error jika ada."),
            ("Scenario Metrics", "Confusion matrix dan metrik untuk RAG-LLM dan Zero-Shot. CodeBERT tidak muncul di sini karena belum melakukan inference."),
            ("Finding Detail", "Detail package-level: prediksi model, ground truth, CVE, severity, mitigasi, dan reasoning bilingual."),
            ("False Review", "Sheet False Positive Review dan False Negative Review memisahkan error prediksi agar mudah dianalisis."),
            ("Ground Truth", "Label pembanding dari GitHub API/local advisory/fallback. Ini dasar TP/TN/FP/FN."),
            ("CodeBERT Dataset", "Record dataset yang diekspor: original, semantic_version_normalization, dan safe_dummy_dependency."),
            ("Retrieval Diagnostics", "Jejak sumber advisory yang dipakai untuk tiap project."),
            ("Field Descriptions", "Kamus field JSON dan Excel agar pembaca memahami arti setiap kolom temuan."),
            ("Metric Definitions", "Rumus Accuracy, Precision, Recall, F1, False Positive Ratio, dan confusion matrix."),
            ("JSON Reports", "audit-rag-llm*.json dan audit-zero-shot*.json berisi report LLM; audit-codebert*.json berisi dataset baseline; api-diagnostics*.json berisi kesehatan API."),
            ("HTML Report", "audit-interactive-report*.html adalah ringkasan interaktif untuk dibuka di browser dan difilter tanpa membuka Excel.")
        };

        for (var i = 0; i < rows.Count; i++)
        {
            sheet.Cell(i + 2, 1).Value = rows[i].Section;
            sheet.Cell(i + 2, 2).Value = rows[i].HowToRead;
        }

        sheet.Column(1).Width = 28;
        sheet.Column(2).Width = 120;
        sheet.Column(2).Style.Alignment.WrapText = true;
        FormatUsedRangeAsTable(sheet, headers.Length);
    }

    private static void WriteMethodComparisonSheet(XLWorkbook workbook, IReadOnlyCollection<ProjectAuditResult> results)
    {
        var sheet = workbook.Worksheets.Add("Method Comparison");
        var headers = new[]
        {
            "ProjectName", "ProjectKey", "PackageCount",
            "RagStatus", "RagAccuracy", "RagPrecision", "RagRecall", "RagF1",
            "ZeroShotStatus", "ZeroShotAccuracy", "ZeroShotPrecision", "ZeroShotRecall", "ZeroShotF1",
            "CodeBertStatus", "CodeBertRecords", "CodeBertTraining", "CodeBertValidation", "CodeBertTesting", "CodeBertNote"
        };
        WriteHeaders(sheet, headers);

        var row = 2;
        foreach (var project in results)
        {
            var rag = project.Scenarios.FirstOrDefault(x => x.Scenario == AuditScenario.RagLlm);
            var zeroShot = project.Scenarios.FirstOrDefault(x => x.Scenario == AuditScenario.ZeroShot);
            var codeBertRecords = project.CodeBertRecords;

            sheet.Cell(row, 1).Value = project.ProjectName;
            sheet.Cell(row, 2).Value = project.ProjectKey;
            sheet.Cell(row, 3).Value = project.PackageCount;
            sheet.Cell(row, 4).Value = rag?.Status ?? "NOT_RUN";
            WriteMetricCells(sheet, row, 5, rag?.Metrics);
            sheet.Cell(row, 9).Value = zeroShot?.Status ?? "NOT_RUN";
            WriteMetricCells(sheet, row, 10, zeroShot?.Metrics);
            sheet.Cell(row, 14).Value = codeBertRecords.Count > 0 || project.PackageCount == 0 ? "EXPORTED" : "NOT_EXPORTED";
            sheet.Cell(row, 15).Value = codeBertRecords.Count;
            sheet.Cell(row, 16).Value = codeBertRecords.Count(x => x.Split == "training");
            sheet.Cell(row, 17).Value = codeBertRecords.Count(x => x.Split == "validation");
            sheet.Cell(row, 18).Value = codeBertRecords.Count(x => x.Split == "testing");
            sheet.Cell(row, 19).Value = "Dataset exported. Import/train CodeBERT predictions to produce neural baseline metrics.";
            row++;
        }

        if (row > 2)
        {
            sheet.Range(2, 5, row - 1, 8).Style.NumberFormat.Format = "0.00%";
            sheet.Range(2, 10, row - 1, 13).Style.NumberFormat.Format = "0.00%";
        }

        FormatUsedRangeAsTable(sheet, headers.Length);
    }

    private static void WriteMetricCells(IXLWorksheet sheet, int row, int startColumn, EvaluationMetrics? metrics)
    {
        if (metrics is null)
        {
            sheet.Cell(row, startColumn).Value = string.Empty;
            sheet.Cell(row, startColumn + 1).Value = string.Empty;
            sheet.Cell(row, startColumn + 2).Value = string.Empty;
            sheet.Cell(row, startColumn + 3).Value = string.Empty;
            return;
        }

        sheet.Cell(row, startColumn).Value = metrics.Accuracy;
        sheet.Cell(row, startColumn + 1).Value = metrics.Precision;
        sheet.Cell(row, startColumn + 2).Value = metrics.Recall;
        sheet.Cell(row, startColumn + 3).Value = metrics.F1Score;
    }

    private static void WriteProjectStatusSheet(XLWorkbook workbook, IReadOnlyCollection<ProjectAuditResult> results)
    {
        var sheet = workbook.Worksheets.Add("Project Status");
        var headers = new[]
        {
            "ProjectName", "ProjectKey", "ProjectPath", "PackageCount", "Success", "SecurityReferenceSource",
            "RagStatus", "RagSuccess", "RagExcludedFromMetrics", "RagMetricExclusionReason",
            "ZeroShotStatus", "ZeroShotSuccess", "ZeroShotExcludedFromMetrics", "ZeroShotMetricExclusionReason",
            "CodeBertRecords", "ElapsedSeconds", "ErrorMessage"
        };
        WriteHeaders(sheet, headers);

        var row = 2;
        foreach (var project in results)
        {
            sheet.Cell(row, 1).Value = project.ProjectName;
            sheet.Cell(row, 2).Value = project.ProjectKey;
            sheet.Cell(row, 3).Value = project.ProjectPath;
            sheet.Cell(row, 4).Value = project.PackageCount;
            sheet.Cell(row, 5).Value = project.Success;
            sheet.Cell(row, 6).Value = project.SecurityReferenceSource;
            var rag = project.Scenarios.FirstOrDefault(x => x.Scenario == AuditScenario.RagLlm);
            var zeroShot = project.Scenarios.FirstOrDefault(x => x.Scenario == AuditScenario.ZeroShot);
            sheet.Cell(row, 7).Value = rag?.Status ?? "NOT_RUN";
            sheet.Cell(row, 8).Value = rag?.Success ?? false;
            sheet.Cell(row, 9).Value = rag?.ExcludedFromMetrics ?? true;
            sheet.Cell(row, 10).Value = rag?.MetricExclusionReason ?? string.Empty;
            sheet.Cell(row, 11).Value = zeroShot?.Status ?? "NOT_RUN";
            sheet.Cell(row, 12).Value = zeroShot?.Success ?? false;
            sheet.Cell(row, 13).Value = zeroShot?.ExcludedFromMetrics ?? true;
            sheet.Cell(row, 14).Value = zeroShot?.MetricExclusionReason ?? string.Empty;
            sheet.Cell(row, 15).Value = project.CodeBertRecords.Count;
            sheet.Cell(row, 16).Value = project.ElapsedSeconds;
            sheet.Cell(row, 17).Value = project.ErrorMessage;
            row++;
        }

        FormatUsedRangeAsTable(sheet, headers.Length);
    }

    private static void WriteScenarioMetricsSheet(XLWorkbook workbook, IReadOnlyCollection<ProjectAuditResult> results)
    {
        var sheet = workbook.Worksheets.Add("Scenario Metrics");
        var headers = new[] { "ProjectName", "ProjectKey", "Scenario", "Total", "TP", "TN", "FP", "FN", "Accuracy", "Precision", "Recall", "F1Score", "FalsePositiveRatio" };
        WriteHeaders(sheet, headers);

        var row = 2;
        foreach (var project in results)
        {
            foreach (var scenario in project.Scenarios.Where(x => x.Metrics is not null))
            {
                var metrics = scenario.Metrics!;
                sheet.Cell(row, 1).Value = project.ProjectName;
                sheet.Cell(row, 2).Value = project.ProjectKey;
                sheet.Cell(row, 3).Value = GetScenarioDisplayName(scenario.Scenario);
                sheet.Cell(row, 4).Value = metrics.Total;
                sheet.Cell(row, 5).Value = metrics.TruePositive;
                sheet.Cell(row, 6).Value = metrics.TrueNegative;
                sheet.Cell(row, 7).Value = metrics.FalsePositive;
                sheet.Cell(row, 8).Value = metrics.FalseNegative;
                sheet.Cell(row, 9).Value = metrics.Accuracy;
                sheet.Cell(row, 10).Value = metrics.Precision;
                sheet.Cell(row, 11).Value = metrics.Recall;
                sheet.Cell(row, 12).Value = metrics.F1Score;
                sheet.Cell(row, 13).Value = metrics.FalsePositiveRatio;
                row++;
            }
        }

        if (row > 2)
        {
            sheet.Range(2, 9, row - 1, 13).Style.NumberFormat.Format = "0.00%";
        }

        FormatUsedRangeAsTable(sheet, headers.Length);
    }

    private static void WriteFindingDetailSheet(XLWorkbook workbook, IReadOnlyCollection<ProjectAuditResult> results)
    {
        var sheet = workbook.Worksheets.Add("Finding Detail");
        var headers = new[]
        {
            "ProjectName", "ProjectKey", "Scenario", "PackageName", "CurrentVersion", "PredictedVulnerable",
            "GroundTruthVulnerable", "MatchResult", "CVE_ID", "Severity", "SeverityIndonesia", "Grounded",
            "MitigationPlan", "MitigationPlanIndonesia", "ReasoningTrace", "ReasoningTraceIndonesia",
            "GroundTruthSeverity", "GroundTruthAdvisoryId", "GroundTruthVulnerableRange", "GroundTruthFirstPatchedVersion",
            "GroundTruthReferenceUrl", "GroundTruthVersionRangeMatched", "GroundTruthVersionRangeEvaluation"
        };
        WriteHeaders(sheet, headers);

        var row = 2;
        foreach (var project in results)
        {
            foreach (var scenario in project.Scenarios.Where(x => x.Metrics is not null))
            {
                var reportLookup = scenario.Response?.VulnerabilityReports
                    .Where(x => !string.IsNullOrWhiteSpace(x.PackageName))
                    .GroupBy(x => x.PackageName, StringComparer.OrdinalIgnoreCase)
                    .ToDictionary(x => x.Key, x => x.First(), StringComparer.OrdinalIgnoreCase)
                    ?? new Dictionary<string, VulnerabilityReport>(StringComparer.OrdinalIgnoreCase);
                var groundTruthLookup = project.GroundTruthLabels
                    .Where(x => !string.IsNullOrWhiteSpace(x.PackageName))
                    .GroupBy(x => x.PackageName, StringComparer.OrdinalIgnoreCase)
                    .ToDictionary(x => x.Key, x => x.First(), StringComparer.OrdinalIgnoreCase);

                foreach (var record in scenario.Metrics!.Records)
                {
                    reportLookup.TryGetValue(record.PackageName, out var report);
                    groundTruthLookup.TryGetValue(record.PackageName, out var groundTruth);
                    sheet.Cell(row, 1).Value = project.ProjectName;
                    sheet.Cell(row, 2).Value = project.ProjectKey;
                    sheet.Cell(row, 3).Value = GetScenarioDisplayName(scenario.Scenario);
                    sheet.Cell(row, 4).Value = record.PackageName;
                    sheet.Cell(row, 5).Value = record.CurrentVersion;
                    sheet.Cell(row, 6).Value = record.PredictedVulnerable;
                    sheet.Cell(row, 7).Value = record.GroundTruthVulnerable;
                    sheet.Cell(row, 8).Value = record.MatchResult;
                    sheet.Cell(row, 9).Value = record.CVE_ID;
                    sheet.Cell(row, 10).Value = record.Severity;
                    sheet.Cell(row, 11).Value = report?.SeverityIndonesia ?? string.Empty;
                    sheet.Cell(row, 12).Value = record.IsGroundedInReference;
                    sheet.Cell(row, 13).Value = report?.MitigationPlan ?? string.Empty;
                    sheet.Cell(row, 14).Value = report?.MitigationPlanIndonesia ?? string.Empty;
                    sheet.Cell(row, 15).Value = report?.ReasoningTrace ?? string.Empty;
                    sheet.Cell(row, 16).Value = report?.ReasoningTraceIndonesia ?? string.Empty;
                    sheet.Cell(row, 17).Value = groundTruth?.Severity ?? string.Empty;
                    sheet.Cell(row, 18).Value = groundTruth?.AdvisoryId ?? string.Empty;
                    sheet.Cell(row, 19).Value = groundTruth?.VulnerableVersionRange ?? string.Empty;
                    sheet.Cell(row, 20).Value = groundTruth?.FirstPatchedVersion ?? string.Empty;
                    sheet.Cell(row, 21).Value = groundTruth?.ReferenceUrl ?? string.Empty;
                    sheet.Cell(row, 22).Value = groundTruth?.IsVersionRangeMatched ?? false;
                    sheet.Cell(row, 23).Value = groundTruth?.VersionRangeEvaluation ?? string.Empty;
                    row++;
                }
            }
        }

        FormatUsedRangeAsTable(sheet, headers.Length);
    }

    private static void WriteFalseReviewSheet(
        XLWorkbook workbook,
        IReadOnlyCollection<ProjectAuditResult> results,
        string sheetName,
        string matchResult)
    {
        var sheet = workbook.Worksheets.Add(sheetName);
        var headers = new[]
        {
            "ProjectName", "ProjectKey", "Scenario", "PackageName", "CurrentVersion", "MatchResult",
            "PredictedVulnerable", "GroundTruthVulnerable", "CVE_ID", "Severity", "Grounded",
            "GroundTruthAdvisoryId", "GroundTruthVulnerableRange", "GroundTruthFirstPatchedVersion",
            "GroundTruthReferenceUrl", "VersionRangeEvaluation", "SuggestedReview"
        };
        WriteHeaders(sheet, headers);

        var row = 2;
        foreach (var project in results)
        {
            var groundTruthLookup = project.GroundTruthLabels
                .Where(x => !string.IsNullOrWhiteSpace(x.PackageName))
                .GroupBy(x => x.PackageName, StringComparer.OrdinalIgnoreCase)
                .ToDictionary(x => x.Key, x => x.First(), StringComparer.OrdinalIgnoreCase);

            foreach (var scenario in project.Scenarios.Where(x => x.Metrics is not null))
            {
                foreach (var record in scenario.Metrics!.Records.Where(x => x.MatchResult == matchResult))
                {
                    groundTruthLookup.TryGetValue(record.PackageName, out var groundTruth);
                    sheet.Cell(row, 1).Value = project.ProjectName;
                    sheet.Cell(row, 2).Value = project.ProjectKey;
                    sheet.Cell(row, 3).Value = GetScenarioDisplayName(scenario.Scenario);
                    sheet.Cell(row, 4).Value = record.PackageName;
                    sheet.Cell(row, 5).Value = record.CurrentVersion;
                    sheet.Cell(row, 6).Value = record.MatchResult;
                    sheet.Cell(row, 7).Value = record.PredictedVulnerable;
                    sheet.Cell(row, 8).Value = record.GroundTruthVulnerable;
                    sheet.Cell(row, 9).Value = record.CVE_ID;
                    sheet.Cell(row, 10).Value = record.Severity;
                    sheet.Cell(row, 11).Value = record.IsGroundedInReference;
                    sheet.Cell(row, 12).Value = groundTruth?.AdvisoryId ?? string.Empty;
                    sheet.Cell(row, 13).Value = groundTruth?.VulnerableVersionRange ?? string.Empty;
                    sheet.Cell(row, 14).Value = groundTruth?.FirstPatchedVersion ?? string.Empty;
                    sheet.Cell(row, 15).Value = groundTruth?.ReferenceUrl ?? string.Empty;
                    sheet.Cell(row, 16).Value = groundTruth?.VersionRangeEvaluation ?? string.Empty;
                    sheet.Cell(row, 17).Value = matchResult == "False Positive"
                        ? "Check whether LLM hallucinated an advisory or ground truth range is missing."
                        : "Check whether prompt/reference context made the model too conservative.";
                    row++;
                }
            }
        }

        FormatUsedRangeAsTable(sheet, headers.Length);
    }

    private static void WriteCodeBertSheet(XLWorkbook workbook, IReadOnlyCollection<ProjectAuditResult> results)
    {
        var sheet = workbook.Worksheets.Add("CodeBERT Dataset");
        var headers = new[]
        {
            "ProjectName", "ProjectKey", "Split", "PackageName", "CurrentVersion", "MutatedPackageName",
            "MutatedVersion", "Label", "LabelId", "AugmentationType", "CVE_ID", "Severity", "AdvisoryId", "CsprojSnippet"
        };
        WriteHeaders(sheet, headers);

        var row = 2;
        foreach (var project in results)
        {
            foreach (var record in project.CodeBertRecords)
            {
                sheet.Cell(row, 1).Value = project.ProjectName;
                sheet.Cell(row, 2).Value = project.ProjectKey;
                sheet.Cell(row, 3).Value = record.Split;
                sheet.Cell(row, 4).Value = record.PackageName;
                sheet.Cell(row, 5).Value = record.CurrentVersion;
                sheet.Cell(row, 6).Value = record.MutatedPackageName;
                sheet.Cell(row, 7).Value = record.MutatedVersion;
                sheet.Cell(row, 8).Value = record.Label;
                sheet.Cell(row, 9).Value = record.LabelId;
                sheet.Cell(row, 10).Value = record.AugmentationType;
                sheet.Cell(row, 11).Value = record.CVE_ID;
                sheet.Cell(row, 12).Value = record.Severity;
                sheet.Cell(row, 13).Value = record.AdvisoryId;
                sheet.Cell(row, 14).Value = record.CsprojSnippet;
                row++;
            }
        }

        FormatUsedRangeAsTable(sheet, headers.Length);
    }

    private static void WriteGroundTruthSheet(XLWorkbook workbook, IReadOnlyCollection<ProjectAuditResult> results)
    {
        var sheet = workbook.Worksheets.Add("Ground Truth");
        var headers = new[]
        {
            "ProjectName", "ProjectKey", "PackageName", "CurrentVersion", "IsVulnerable",
            "CVE_ID", "Severity", "AdvisoryId", "VulnerableVersionRange", "FirstPatchedVersion", "ReferenceUrl",
            "IsVersionRangeMatched", "VersionRangeEvaluation"
        };
        WriteHeaders(sheet, headers);

        var row = 2;
        foreach (var project in results)
        {
            foreach (var label in project.GroundTruthLabels)
            {
                sheet.Cell(row, 1).Value = project.ProjectName;
                sheet.Cell(row, 2).Value = project.ProjectKey;
                sheet.Cell(row, 3).Value = label.PackageName;
                sheet.Cell(row, 4).Value = label.CurrentVersion;
                sheet.Cell(row, 5).Value = label.IsVulnerable;
                sheet.Cell(row, 6).Value = label.CVE_ID;
                sheet.Cell(row, 7).Value = label.Severity;
                sheet.Cell(row, 8).Value = label.AdvisoryId;
                sheet.Cell(row, 9).Value = label.VulnerableVersionRange;
                sheet.Cell(row, 10).Value = label.FirstPatchedVersion;
                sheet.Cell(row, 11).Value = label.ReferenceUrl;
                sheet.Cell(row, 12).Value = label.IsVersionRangeMatched;
                sheet.Cell(row, 13).Value = label.VersionRangeEvaluation;
                row++;
            }
        }

        FormatUsedRangeAsTable(sheet, headers.Length);
    }

    private static void WriteCodeBertEvaluationSheet(XLWorkbook workbook, IReadOnlyCollection<ProjectAuditResult> results)
    {
        var sheet = workbook.Worksheets.Add("CodeBERT Evaluation");
        var headers = new[] { "ProjectName", "ProjectKey", "Status", "DatasetRecords", "Training", "Validation", "Testing", "Explanation" };
        WriteHeaders(sheet, headers);

        var row = 2;
        foreach (var project in results)
        {
            sheet.Cell(row, 1).Value = project.ProjectName;
            sheet.Cell(row, 2).Value = project.ProjectKey;
            sheet.Cell(row, 3).Value = project.CodeBertRecords.Count > 0 || project.PackageCount == 0 ? "DATASET_EXPORTED" : "NOT_EXPORTED";
            sheet.Cell(row, 4).Value = project.CodeBertRecords.Count;
            sheet.Cell(row, 5).Value = project.CodeBertRecords.Count(x => x.Split == "training");
            sheet.Cell(row, 6).Value = project.CodeBertRecords.Count(x => x.Split == "validation");
            sheet.Cell(row, 7).Value = project.CodeBertRecords.Count(x => x.Split == "testing");
            sheet.Cell(row, 8).Value = "Neural CodeBERT metrics require training/inference output. This sheet prevents treating dataset export as model prediction.";
            row++;
        }

        FormatUsedRangeAsTable(sheet, headers.Length);
    }

    private static void WriteRetrievalDiagnosticsSheet(XLWorkbook workbook, IReadOnlyCollection<ProjectAuditResult> results)
    {
        var sheet = workbook.Worksheets.Add("Retrieval Diagnostics");
        var headers = new[] { "ProjectName", "ProjectKey", "Source", "Diagnostic" };
        WriteHeaders(sheet, headers);

        var row = 2;
        foreach (var project in results)
        {
            foreach (var diagnostic in project.RetrievalDiagnostics)
            {
                sheet.Cell(row, 1).Value = project.ProjectName;
                sheet.Cell(row, 2).Value = project.ProjectKey;
                sheet.Cell(row, 3).Value = project.SecurityReferenceSource;
                sheet.Cell(row, 4).Value = diagnostic;
                row++;
            }
        }

        FormatUsedRangeAsTable(sheet, headers.Length);
    }

    private static void WriteFieldDescriptionsSheet(XLWorkbook workbook)
    {
        var sheet = workbook.Worksheets.Add("Field Descriptions");
        var headers = new[] { "Field", "Description", "Value", "ValueDescription" };
        WriteHeaders(sheet, headers);

        var row = 2;
        foreach (var field in GetVulnerabilityReportFieldDescriptions())
        {
            if (field.Value.ValueDescriptions.Count == 0)
            {
                sheet.Cell(row, 1).Value = field.Key;
                sheet.Cell(row, 2).Value = field.Value.Description;
                row++;
                continue;
            }

            foreach (var valueDescription in field.Value.ValueDescriptions)
            {
                sheet.Cell(row, 1).Value = field.Key;
                sheet.Cell(row, 2).Value = field.Value.Description;
                sheet.Cell(row, 3).Value = valueDescription.Key;
                sheet.Cell(row, 4).Value = valueDescription.Value;
                row++;
            }
        }

        FormatUsedRangeAsTable(sheet, headers.Length);
    }

    private static void WriteMetricDefinitionsSheet(XLWorkbook workbook)
    {
        var sheet = workbook.Worksheets.Add("Metric Definitions");
        var headers = new[] { "Metric", "Formula", "Description" };
        WriteHeaders(sheet, headers);

        var row = 2;
        foreach (var item in GetMetricFormulaDescriptions())
        {
            sheet.Cell(row, 1).Value = item.Key;
            sheet.Cell(row, 2).Value = item.Value.Formula;
            sheet.Cell(row, 3).Value = item.Value.Description;
            row++;
        }

        FormatUsedRangeAsTable(sheet, headers.Length);
    }

    private static void SaveInteractiveHtmlReport(
        string outputFilePath,
        string rootFolder,
        string modelName,
        IReadOnlyCollection<ProjectAuditResult> results,
        FinalArtifactSet artifactSet)
    {
        var ragResults = results.SelectMany(p => p.Scenarios.Where(s => s.Scenario == AuditScenario.RagLlm).Select(s => (Project: p, Scenario: s))).ToList();
        var zeroShotResults = results.SelectMany(p => p.Scenarios.Where(s => s.Scenario == AuditScenario.ZeroShot).Select(s => (Project: p, Scenario: s))).ToList();
        var allFindings = results
            .SelectMany(project => project.Scenarios.SelectMany(scenario =>
                scenario.Response?.VulnerabilityReports.Select(report => (Project: project, Scenario: scenario, Report: report))
                ?? Enumerable.Empty<(ProjectAuditResult Project, ScenarioAuditResult Scenario, VulnerabilityReport Report)>()))
            .ToList();

        var builder = new StringBuilder();
        builder.AppendLine("<!doctype html>");
        builder.AppendLine("<html lang=\"en\"><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">");
        builder.AppendLine("<title>GeminiNuGetAuditor Interactive Report</title>");
        builder.AppendLine("""
<style>
:root{--bg:#f6f8fb;--panel:#ffffff;--ink:#172033;--muted:#657089;--line:#dbe3ef;--brand:#1d4ed8;--brand2:#0f766e;--good:#15803d;--warn:#b45309;--bad:#b91c1c}
*{box-sizing:border-box} body{margin:0;background:var(--bg);color:var(--ink);font-family:Segoe UI,Roboto,Arial,sans-serif;line-height:1.45}
header{background:linear-gradient(135deg,#0f172a,#1d4ed8 55%,#0f766e);color:white;padding:34px 42px}
header h1{margin:0 0 8px;font-size:30px;letter-spacing:0} header p{margin:0;color:#dbeafe;max-width:980px}
main{padding:24px 42px 48px}.grid{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:14px}.card{background:var(--panel);border:1px solid var(--line);border-radius:8px;padding:16px;box-shadow:0 8px 24px rgba(15,23,42,.06)}
.metric .label{color:var(--muted);font-size:12px;text-transform:uppercase;letter-spacing:.04em}.metric .value{font-size:28px;font-weight:700;margin-top:4px}
section{margin-top:18px}.section-title{display:flex;align-items:end;justify-content:space-between;gap:12px;margin:24px 0 10px}h2{font-size:20px;margin:0}.hint{color:var(--muted);font-size:13px}
table{width:100%;border-collapse:collapse;background:var(--panel);border:1px solid var(--line);border-radius:8px;overflow:hidden}th,td{padding:10px 12px;border-bottom:1px solid var(--line);text-align:left;vertical-align:top;font-size:13px}th{background:#eef4ff;color:#24324b;position:sticky;top:0;z-index:1}tr:hover td{background:#f8fbff}
.pill{display:inline-flex;align-items:center;border-radius:999px;padding:3px 9px;font-size:12px;font-weight:600}.good{background:#dcfce7;color:var(--good)}.bad{background:#fee2e2;color:var(--bad)}.warn{background:#fef3c7;color:var(--warn)}.neutral{background:#e5e7eb;color:#374151}
.toolbar{display:flex;gap:10px;align-items:center;flex-wrap:wrap}.toolbar input{min-width:280px;padding:10px 12px;border:1px solid var(--line);border-radius:8px;background:white}.tabs{display:flex;gap:8px;flex-wrap:wrap}.tab{border:1px solid var(--line);background:white;border-radius:999px;padding:8px 12px;cursor:pointer}.tab.active{background:var(--brand);color:white;border-color:var(--brand)}
.panel{display:none}.panel.active{display:block}.two{display:grid;grid-template-columns:1fr 1fr;gap:14px}.files a{display:block;color:var(--brand);text-decoration:none;margin:6px 0}.files a:hover{text-decoration:underline}
@media(max-width:980px){main,header{padding-left:18px;padding-right:18px}.grid,.two{grid-template-columns:1fr}.toolbar input{min-width:100%;width:100%}}
</style>
""");
        builder.AppendLine("</head><body>");
        builder.AppendLine("<header>");
        builder.AppendLine("<h1>GeminiNuGetAuditor Interactive Report</h1>");
        builder.AppendLine($"<p>Audit root: {Html(rootFolder)} &nbsp; | &nbsp; Model: <strong>{Html(modelName)}</strong> &nbsp; | &nbsp; Generated: {Html(DateTimeOffset.UtcNow.ToString("O"))}</p>");
        builder.AppendLine("</header><main>");

        builder.AppendLine("<section class=\"grid\">");
        AppendMetricCard(builder, "Projects", results.Count.ToString(CultureInfo.InvariantCulture));
        AppendMetricCard(builder, "Successful", results.Count(IsProjectFullySuccessfulForResume).ToString(CultureInfo.InvariantCulture));
        AppendMetricCard(builder, "RAG Findings", ragResults.Sum(x => x.Scenario.Response?.VulnerabilityReports.Count(r => r.IsVulnerable) ?? 0).ToString(CultureInfo.InvariantCulture));
        AppendMetricCard(builder, "Zero-Shot Findings", zeroShotResults.Sum(x => x.Scenario.Response?.VulnerabilityReports.Count(r => r.IsVulnerable) ?? 0).ToString(CultureInfo.InvariantCulture));
        AppendMetricCard(builder, "CodeBERT Records", results.Sum(x => x.CodeBertRecords.Count).ToString(CultureInfo.InvariantCulture));
        AppendMetricCard(builder, "API Failed Scenarios", results.SelectMany(x => x.Scenarios).Count(x => x.Status == "API_FAILED").ToString(CultureInfo.InvariantCulture));
        AppendMetricCard(builder, "Packages", results.Sum(x => x.PackageCount).ToString(CultureInfo.InvariantCulture));
        AppendMetricCard(builder, "Ground Truth Vulnerable", results.Sum(x => x.GroundTruthLabels.Count(g => g.IsVulnerable)).ToString(CultureInfo.InvariantCulture));
        builder.AppendLine("</section>");

        builder.AppendLine("""
<section class="card">
<div class="section-title"><h2>How to read this report</h2><span class="hint">Three outputs are produced: two LLM audit scenarios and one CodeBERT dataset baseline.</span></div>
<div class="two">
<div><strong>RAG-LLM</strong><p>Gemini receives package references plus retrieved security context. Use this as the grounded LLM scenario.</p></div>
<div><strong>Zero-Shot</strong><p>Gemini receives only package references. Compare it with RAG-LLM to measure the effect of retrieval.</p></div>
<div><strong>CodeBERT</strong><p>This run exports labeled dataset rows for a CodeBERT baseline. It is not an LLM prediction table, so it does not appear in the LLM confusion matrix.</p></div>
<div><strong>Ground Truth</strong><p>Labels are built from GitHub GraphQL/local advisory/fallback references and drive TP/TN/FP/FN.</p></div>
</div>
</section>
""");

        AppendComparisonChart(builder, results);

        builder.AppendLine("<section><div class=\"section-title\"><h2>Interactive Tables</h2><div class=\"toolbar\"><input id=\"q\" placeholder=\"Search project, package, CVE, severity...\"><div class=\"tabs\"><button class=\"tab active\" data-tab=\"projects\">Projects</button><button class=\"tab\" data-tab=\"findings\">Findings</button><button class=\"tab\" data-tab=\"errors\">Errors</button><button class=\"tab\" data-tab=\"artifacts\">Artifacts</button></div></div></div>");
        builder.AppendLine("<div id=\"projects\" class=\"panel active\">");
        AppendProjectTable(builder, results);
        builder.AppendLine("</div><div id=\"findings\" class=\"panel\">");
        AppendFindingTable(builder, allFindings);
        builder.AppendLine("</div><div id=\"errors\" class=\"panel\">");
        AppendErrorReviewTable(builder, results);
        builder.AppendLine("</div><div id=\"artifacts\" class=\"panel card files\">");
        AppendArtifactLinks(builder, artifactSet);
        builder.AppendLine("</div></section>");
        builder.AppendLine("""
<script>
const tabs=[...document.querySelectorAll('.tab')],panels=[...document.querySelectorAll('.panel')],q=document.getElementById('q');
tabs.forEach(t=>t.addEventListener('click',()=>{tabs.forEach(x=>x.classList.remove('active'));panels.forEach(p=>p.classList.remove('active'));t.classList.add('active');document.getElementById(t.dataset.tab).classList.add('active');filter()}));
q.addEventListener('input',filter);
function filter(){const term=q.value.toLowerCase();document.querySelectorAll('.panel.active tbody tr').forEach(r=>{r.style.display=r.innerText.toLowerCase().includes(term)?'':'none'})}
</script>
""");
        builder.AppendLine("</main></body></html>");
        File.WriteAllText(outputFilePath, builder.ToString(), Encoding.UTF8);
    }

    private static void AppendMetricCard(StringBuilder builder, string label, string value)
    {
        builder.AppendLine($"<div class=\"card metric\"><div class=\"label\">{Html(label)}</div><div class=\"value\">{Html(value)}</div></div>");
    }

    private static void AppendProjectTable(StringBuilder builder, IReadOnlyCollection<ProjectAuditResult> results)
    {
        builder.AppendLine("<table><thead><tr><th>Project</th><th>Packages</th><th>RAG</th><th>Zero-Shot</th><th>CodeBERT</th><th>Reference</th><th>Elapsed</th></tr></thead><tbody>");
        foreach (var project in results.OrderBy(x => x.ProjectName, StringComparer.OrdinalIgnoreCase))
        {
            var rag = project.Scenarios.FirstOrDefault(x => x.Scenario == AuditScenario.RagLlm);
            var zero = project.Scenarios.FirstOrDefault(x => x.Scenario == AuditScenario.ZeroShot);
            builder.AppendLine("<tr>");
            builder.AppendLine($"<td><strong>{Html(project.ProjectName)}</strong><br><span class=\"hint\">{Html(project.ProjectKey)}</span></td>");
            builder.AppendLine($"<td>{project.PackageCount}</td>");
            builder.AppendLine($"<td>{StatusPill(rag?.Status ?? "NOT_RUN")}<br>{MetricMini(rag?.Metrics)}</td>");
            builder.AppendLine($"<td>{StatusPill(zero?.Status ?? "NOT_RUN")}<br>{MetricMini(zero?.Metrics)}</td>");
            builder.AppendLine($"<td>{StatusPill(project.CodeBertRecords.Count > 0 || project.PackageCount == 0 ? "EXPORTED" : "NOT_EXPORTED")}<br>{project.CodeBertRecords.Count} records</td>");
            builder.AppendLine($"<td>{Html(project.SecurityReferenceSource)}</td>");
            builder.AppendLine($"<td>{project.ElapsedSeconds:0.0}s</td>");
            builder.AppendLine("</tr>");
        }
        builder.AppendLine("</tbody></table>");
    }

    private static void AppendComparisonChart(StringBuilder builder, IReadOnlyCollection<ProjectAuditResult> results)
    {
        var rag = AggregateScenarioMetrics(results, AuditScenario.RagLlm);
        var zero = AggregateScenarioMetrics(results, AuditScenario.ZeroShot);
        builder.AppendLine("<section class=\"card\"><div class=\"section-title\"><h2>RAG-LLM vs Zero-Shot</h2><span class=\"hint\">Aggregate metrics across all evaluated packages.</span></div>");
        builder.AppendLine("<div class=\"two\">");
        AppendBarGroup(builder, "Accuracy", rag.Accuracy, zero.Accuracy);
        AppendBarGroup(builder, "Precision", rag.Precision, zero.Precision);
        AppendBarGroup(builder, "Recall", rag.Recall, zero.Recall);
        AppendBarGroup(builder, "F1Score", rag.F1Score, zero.F1Score);
        builder.AppendLine("</div></section>");
    }

    private static void AppendBarGroup(StringBuilder builder, string label, double rag, double zero)
    {
        builder.AppendLine("<div>");
        builder.AppendLine($"<strong>{Html(label)}</strong>");
        AppendBar(builder, "RAG-LLM", rag, "#1d4ed8");
        AppendBar(builder, "Zero-Shot", zero, "#0f766e");
        builder.AppendLine("</div>");
    }

    private static void AppendBar(StringBuilder builder, string label, double value, string color)
    {
        var pct = Math.Clamp(value, 0d, 1d) * 100d;
        builder.AppendLine($"<div class=\"hint\" style=\"margin-top:8px\">{Html(label)} {pct:0.0}%</div>");
        builder.AppendLine($"<div style=\"height:12px;background:#e5e7eb;border-radius:999px;overflow:hidden\"><div style=\"height:12px;width:{pct:0.##}%;background:{color}\"></div></div>");
    }

    private static void AppendFindingTable(
        StringBuilder builder,
        IReadOnlyCollection<(ProjectAuditResult Project, ScenarioAuditResult Scenario, VulnerabilityReport Report)> findings)
    {
        builder.AppendLine("<table><thead><tr><th>Project</th><th>Scenario</th><th>Package</th><th>Version</th><th>Vulnerable</th><th>CVE</th><th>Severity</th><th>Grounded</th><th>Mitigation</th></tr></thead><tbody>");
        foreach (var item in findings.OrderByDescending(x => x.Report.IsVulnerable).ThenBy(x => x.Project.ProjectName).ThenBy(x => x.Report.PackageName))
        {
            builder.AppendLine("<tr>");
            builder.AppendLine($"<td>{Html(item.Project.ProjectName)}</td>");
            builder.AppendLine($"<td>{Html(GetScenarioDisplayName(item.Scenario.Scenario))}</td>");
            builder.AppendLine($"<td>{Html(item.Report.PackageName)}</td>");
            builder.AppendLine($"<td>{Html(item.Report.CurrentVersion)}</td>");
            builder.AppendLine($"<td>{StatusPill(item.Report.IsVulnerable ? "VULNERABLE" : "SAFE")}</td>");
            builder.AppendLine($"<td>{Html(item.Report.CVE_ID)}</td>");
            builder.AppendLine($"<td>{Html(item.Report.Severity)}</td>");
            builder.AppendLine($"<td>{StatusPill(item.Report.IsGroundedInReference ? "GROUNDED" : "UNGROUNDED")}</td>");
            builder.AppendLine($"<td>{Html(TruncateForDisplay(item.Report.MitigationPlanIndonesia, 240))}</td>");
            builder.AppendLine("</tr>");
        }
        builder.AppendLine("</tbody></table>");
    }

    private static void AppendErrorReviewTable(StringBuilder builder, IReadOnlyCollection<ProjectAuditResult> results)
    {
        builder.AppendLine("<table><thead><tr><th>Project</th><th>Scenario</th><th>Package</th><th>Version</th><th>Error</th><th>CVE</th><th>Range</th><th>Version Evaluation</th><th>Review Hint</th></tr></thead><tbody>");
        foreach (var project in results)
        {
            var groundTruthLookup = project.GroundTruthLabels
                .Where(x => !string.IsNullOrWhiteSpace(x.PackageName))
                .GroupBy(x => x.PackageName, StringComparer.OrdinalIgnoreCase)
                .ToDictionary(x => x.Key, x => x.First(), StringComparer.OrdinalIgnoreCase);

            foreach (var scenario in project.Scenarios.Where(x => x.Metrics is not null))
            {
                foreach (var record in scenario.Metrics!.Records.Where(x => x.MatchResult is "False Positive" or "False Negative"))
                {
                    groundTruthLookup.TryGetValue(record.PackageName, out var groundTruth);
                    builder.AppendLine("<tr>");
                    builder.AppendLine($"<td>{Html(project.ProjectName)}</td>");
                    builder.AppendLine($"<td>{Html(GetScenarioDisplayName(scenario.Scenario))}</td>");
                    builder.AppendLine($"<td>{Html(record.PackageName)}</td>");
                    builder.AppendLine($"<td>{Html(record.CurrentVersion)}</td>");
                    builder.AppendLine($"<td>{StatusPill(record.MatchResult)}</td>");
                    builder.AppendLine($"<td>{Html(record.CVE_ID)}</td>");
                    builder.AppendLine($"<td>{Html(groundTruth?.VulnerableVersionRange)}</td>");
                    builder.AppendLine($"<td>{Html(groundTruth?.VersionRangeEvaluation)}</td>");
                    builder.AppendLine($"<td>{Html(record.MatchResult == "False Positive" ? "Check hallucination or missing advisory range." : "Check conservative prompt/reference interpretation.")}</td>");
                    builder.AppendLine("</tr>");
                }
            }
        }
        builder.AppendLine("</tbody></table>");
    }

    private static void AppendArtifactLinks(StringBuilder builder, FinalArtifactSet artifactSet)
    {
        var artifacts = new[]
        {
            ("RAG-LLM JSON", artifactSet.RagJsonPath),
            ("Zero-Shot JSON", artifactSet.ZeroShotJsonPath),
            ("CodeBERT JSON", artifactSet.CodeBertJsonPath),
            ("Excel Workbook", artifactSet.ExcelReportPath),
            ("API Diagnostics JSON", artifactSet.ApiDiagnosticsJsonPath),
            ("Console Log JSON", artifactSet.ConsoleLogJsonPath)
        };

        foreach (var (label, path) in artifacts)
        {
            builder.AppendLine($"<a href=\"{Html(Path.GetFileName(path))}\">{Html(label)} - {Html(Path.GetFileName(path))}</a>");
        }
    }

    private static string MetricMini(EvaluationMetrics? metrics)
    {
        return metrics is null
            ? "<span class=\"hint\">No metrics</span>"
            : $"<span class=\"hint\">Acc {metrics.Accuracy:P1} | P {metrics.Precision:P1} | R {metrics.Recall:P1} | F1 {metrics.F1Score:P1}</span>";
    }

    private static string StatusPill(string status)
    {
        var css = status switch
        {
            "SUCCESS" or "EXPORTED" or "SAFE" or "GROUNDED" => "good",
            "API_FAILED" or "NOT_EXPORTED" or "VULNERABLE" or "False Positive" or "False Negative" => "bad",
            "NOT_RUN" or "UNGROUNDED" => "warn",
            _ => "neutral"
        };
        return $"<span class=\"pill {css}\">{Html(status)}</span>";
    }

    private static string Html(string? value)
    {
        return WebUtility.HtmlEncode(value ?? string.Empty);
    }

    private static void WriteHeaders(IXLWorksheet sheet, IReadOnlyList<string> headers)
    {
        for (var i = 0; i < headers.Count; i++)
        {
            sheet.Cell(1, i + 1).Value = headers[i];
        }
    }

    private static void FormatUsedRangeAsTable(IXLWorksheet sheet, int columnCount)
    {
        var lastRow = Math.Max(1, sheet.LastRowUsed()?.RowNumber() ?? 1);
        var range = sheet.Range(1, 1, lastRow, columnCount);
        range.Style.Border.OutsideBorder = XLBorderStyleValues.Thin;
        range.Style.Border.InsideBorder = XLBorderStyleValues.Thin;
        sheet.Range(1, 1, 1, columnCount).Style.Font.Bold = true;
        sheet.Range(1, 1, 1, columnCount).Style.Fill.BackgroundColor = XLColor.LightGray;
        sheet.SheetView.FreezeRows(1);
        range.SetAutoFilter();
        sheet.Columns().AdjustToContents();
    }

    private static string BuildProjectKey(string csprojPath)
    {
        var projectName = Path.GetFileNameWithoutExtension(csprojPath);
        var hash = StableHash(Path.GetFullPath(csprojPath)).ToString("X8");
        return SanitizeFileName($"{projectName}-{hash}");
    }

    private static string SanitizeFileName(string value)
    {
        var invalid = Path.GetInvalidFileNameChars().ToHashSet();
        var builder = new StringBuilder(value.Length);

        foreach (var character in value)
        {
            builder.Append(invalid.Contains(character) ? '-' : character);
        }

        return builder.ToString();
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

    private static TimeSpan CalculateBackoffDelay(int baseDelayMilliseconds, int attempt)
    {
        var exponential = Math.Pow(2, Math.Max(0, attempt - 1));
        var jitter = Random.Shared.Next(100, 500);
        var delay = Math.Min(30000, (int)(baseDelayMilliseconds * exponential) + jitter);
        return TimeSpan.FromMilliseconds(delay);
    }

    private static bool IsTransientStatusCode(HttpStatusCode? statusCode)
    {
        if (!statusCode.HasValue)
        {
            return true;
        }

        return statusCode == HttpStatusCode.TooManyRequests || (int)statusCode.Value >= 500;
    }

    private static string GetScenarioTag(AuditScenario scenario)
    {
        return scenario switch
        {
            AuditScenario.RagLlm => "rag-llm",
            AuditScenario.ZeroShot => "zero-shot",
            AuditScenario.CodeBert => "codebert",
            _ => "unknown"
        };
    }

    private static string GetScenarioDisplayName(AuditScenario scenario)
    {
        return scenario switch
        {
            AuditScenario.RagLlm => "RAG-LLM",
            AuditScenario.ZeroShot => "Zero-Shot",
            AuditScenario.CodeBert => "CodeBERT",
            _ => "Unknown"
        };
    }

    private static string GetApplicationRootDirectory()
    {
        var currentDirectory = new DirectoryInfo(Path.GetFullPath(Directory.GetCurrentDirectory()));

        while (currentDirectory is not null)
        {
            if (currentDirectory.GetFiles("*.sln").Any() ||
                currentDirectory.GetFiles("*.slnx").Any() ||
                currentDirectory.GetFiles("*.csproj").Any())
            {
                return currentDirectory.FullName;
            }

            currentDirectory = currentDirectory.Parent;
        }

        return Directory.GetCurrentDirectory();
    }

    private static bool IsUsableApiKey(string? apiKey)
    {
        return !string.IsNullOrWhiteSpace(apiKey) &&
               !string.Equals(apiKey, "sample", StringComparison.OrdinalIgnoreCase);
    }

    private static Dictionary<string, VulnerabilityFieldDescription> GetVulnerabilityReportFieldDescriptions()
    {
        return new Dictionary<string, VulnerabilityFieldDescription>
        {
            ["PackageName"] = new VulnerabilityFieldDescription { Description = "Nama paket NuGet yang dianalisis." },
            ["CurrentVersion"] = new VulnerabilityFieldDescription { Description = "Versi paket yang saat ini digunakan pada proyek target." },
            ["IsVulnerable"] = new VulnerabilityFieldDescription
            {
                Description = "Status apakah paket terdeteksi rentan berdasarkan analisis.",
                ValueDescriptions = new Dictionary<string, string>
                {
                    ["true"] = "Paket terindikasi memiliki kerentanan.",
                    ["false"] = "Tidak ada kerentanan yang teridentifikasi untuk paket ini pada referensi yang tersedia."
                }
            },
            ["CVE_ID"] = new VulnerabilityFieldDescription { Description = "Identifier CVE yang terkait dengan kerentanan, jika tersedia." },
            ["Severity"] = new VulnerabilityFieldDescription { Description = "Tingkat keparahan kerentanan dalam bahasa Inggris." },
            ["SeverityIndonesia"] = new VulnerabilityFieldDescription { Description = "Tingkat keparahan kerentanan dalam bahasa Indonesia." },
            ["MitigationPlan"] = new VulnerabilityFieldDescription { Description = "Rencana mitigasi atau rekomendasi perbaikan dalam bahasa Inggris." },
            ["MitigationPlanIndonesia"] = new VulnerabilityFieldDescription { Description = "Rencana mitigasi atau rekomendasi perbaikan dalam bahasa Indonesia." },
            ["IsGroundedInReference"] = new VulnerabilityFieldDescription { Description = "Status apakah temuan didukung oleh data referensi keamanan yang diberikan." },
            ["ReasoningTrace"] = new VulnerabilityFieldDescription { Description = "Ringkasan alasan analisis model dalam bahasa Inggris." },
            ["ReasoningTraceIndonesia"] = new VulnerabilityFieldDescription { Description = "Ringkasan alasan analisis model dalam bahasa Indonesia." }
        };
    }

    private static Dictionary<string, MetricFormulaDescription> GetMetricFormulaDescriptions()
    {
        return new Dictionary<string, MetricFormulaDescription>
        {
            ["True Positive"] = new MetricFormulaDescription
            {
                Formula = "PredictedVulnerable = true AND GroundTruthVulnerable = true",
                Description = "Model menandai package rentan dan ground truth juga menyatakan package rentan."
            },
            ["True Negative"] = new MetricFormulaDescription
            {
                Formula = "PredictedVulnerable = false AND GroundTruthVulnerable = false",
                Description = "Model menandai package tidak rentan dan ground truth juga menyatakan package tidak rentan."
            },
            ["False Positive"] = new MetricFormulaDescription
            {
                Formula = "PredictedVulnerable = true AND GroundTruthVulnerable = false",
                Description = "Model menandai package rentan padahal ground truth tidak rentan. Ini indikator hallucination/slopsquatting risk."
            },
            ["False Negative"] = new MetricFormulaDescription
            {
                Formula = "PredictedVulnerable = false AND GroundTruthVulnerable = true",
                Description = "Model gagal mendeteksi package yang sebenarnya rentan menurut ground truth."
            },
            ["Accuracy"] = new MetricFormulaDescription
            {
                Formula = "(TP + TN) / (TP + TN + FP + FN)",
                Description = "Proporsi seluruh prediksi yang benar."
            },
            ["Precision"] = new MetricFormulaDescription
            {
                Formula = "TP / (TP + FP)",
                Description = "Ketepatan prediksi rentan. Metrik utama untuk menekan false positive."
            },
            ["Recall"] = new MetricFormulaDescription
            {
                Formula = "TP / (TP + FN)",
                Description = "Kemampuan menemukan seluruh package yang benar-benar rentan."
            },
            ["F1-Score"] = new MetricFormulaDescription
            {
                Formula = "2 x Precision x Recall / (Precision + Recall)",
                Description = "Rata-rata harmonik Precision dan Recall."
            },
            ["FalsePositiveRatio"] = new MetricFormulaDescription
            {
                Formula = "FP / (TP + FP)",
                Description = "Rasio alarm palsu dari seluruh prediksi positif."
            }
        };
    }

    private static Dictionary<string, string> GetCodeBertDatasetFieldDescriptions()
    {
        return new Dictionary<string, string>
        {
            ["Id"] = "Identifier deterministik untuk record dataset.",
            ["Split"] = "Bagian dataset: training, validation, atau testing.",
            ["PackageName"] = "Nama package asli dari file .csproj.",
            ["CurrentVersion"] = "Versi package asli dari file .csproj.",
            ["MutatedPackageName"] = "Nama package setelah augmentasi.",
            ["MutatedVersion"] = "Versi package setelah augmentasi.",
            ["CsprojSnippet"] = "Potongan XML .csproj yang digunakan sebagai input model CodeBERT.",
            ["Label"] = "Ground truth boolean. true berarti vulnerable.",
            ["LabelId"] = "Ground truth numerik. 1 berarti vulnerable, 0 berarti not vulnerable.",
            ["AugmentationType"] = "Jenis augmentasi: original, semantic_version_normalization, atau safe_dummy_dependency.",
            ["CVE_ID"] = "Identifier CVE dari ground truth jika tersedia.",
            ["Severity"] = "Severity dari advisory ground truth jika tersedia.",
            ["AdvisoryId"] = "Identifier advisory seperti GHSA jika tersedia."
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

    private static void AddGeminiApiDiagnostic(GeminiApiDiagnostic diagnostic)
    {
        GeminiApiDiagnostics.Add(diagnostic);
    }

    private static void InstallConsoleCapture()
    {
        if (Console.Out is CapturingConsoleWriter)
        {
            return;
        }

        Console.SetOut(new CapturingConsoleWriter(Console.Out, "stdout", Console.OutputEncoding));
        Console.SetError(new CapturingConsoleWriter(Console.Error, "stderr", Console.OutputEncoding));
    }

    private static void AddConsoleLog(string stream, string message, bool endsLine)
    {
        ConsoleLogEntries.Enqueue(new ConsoleLogEntry
        {
            Sequence = Interlocked.Increment(ref ConsoleLogSequence),
            TimestampUtc = DateTimeOffset.UtcNow,
            Stream = stream,
            Message = message,
            EndsLine = endsLine
        });
    }

    private static void SaveConsoleLogJson(string outputFilePath)
    {
        var entries = ConsoleLogEntries
            .OrderBy(x => x.Sequence)
            .ToList();

        var report = new ConsoleExecutionLogReport
        {
            GeneratedAtUtc = DateTimeOffset.UtcNow,
            EntryCount = entries.Count,
            FullText = BuildConsoleFullText(entries),
            Entries = entries
        };

        File.WriteAllText(outputFilePath, JsonSerializer.Serialize(report, SerializerOptions), Encoding.UTF8);
    }

    private static string BuildConsoleFullText(IEnumerable<ConsoleLogEntry> entries)
    {
        var builder = new StringBuilder();

        foreach (var entry in entries.OrderBy(x => x.Sequence))
        {
            builder.Append(entry.Message);

            if (entry.EndsLine)
            {
                builder.AppendLine();
            }
        }

        return builder.ToString();
    }

    private static Dictionary<string, List<string>> CollectHeaders(HttpResponseMessage response)
    {
        var headers = new Dictionary<string, List<string>>(StringComparer.OrdinalIgnoreCase);

        foreach (var header in response.Headers)
        {
            headers[header.Key] = header.Value.ToList();
        }

        foreach (var header in response.Content.Headers)
        {
            headers[header.Key] = header.Value.ToList();
        }

        return headers;
    }

    private static Dictionary<string, List<string>> CollectRateLimitHeaders(HttpResponseMessage response)
    {
        return CollectHeaders(response)
            .Where(x =>
                x.Key.Contains("rate", StringComparison.OrdinalIgnoreCase) ||
                x.Key.Contains("quota", StringComparison.OrdinalIgnoreCase) ||
                x.Key.Contains("limit", StringComparison.OrdinalIgnoreCase) ||
                x.Key.Contains("retry-after", StringComparison.OrdinalIgnoreCase))
            .ToDictionary(x => x.Key, x => x.Value, StringComparer.OrdinalIgnoreCase);
    }

    private static void WriteLine(string message)
    {
        lock (ConsoleLock)
        {
            Console.WriteLine(message);
        }
    }

    private static void WriteError(string message)
    {
        lock (ConsoleLock)
        {
            Console.Error.WriteLine(message);
        }
    }

    private sealed class GeminiConfigurationException(string message) : Exception(message)
    {
    }

    private sealed class GeminiApiFailedException(string message) : Exception(message)
    {
    }

    private sealed class GeminiSettings
    {
        public string ApiKey { get; set; } = string.Empty;
        public string Model { get; set; } = "gemini-2.5-pro";
        public string GenerateContentEndpointTemplate { get; set; } = "https://generativelanguage.googleapis.com/v1/models/{0}:generateContent";
        public int RequestTimeoutSeconds { get; set; } = 300;
        public int MaxPackagesPerRequest { get; set; } = 15;
        public int MaxRetryCount { get; set; } = 5;
        public int RetryDelayMilliseconds { get; set; } = 5000;
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

    private sealed class GeminiModelListResponse
    {
        [JsonPropertyName("models")]
        public List<GeminiModelMetadata>? Models { get; set; }
    }

    private sealed class GeminiModelMetadata
    {
        [JsonPropertyName("name")]
        public string Name { get; set; } = string.Empty;

        [JsonPropertyName("supportedGenerationMethods")]
        public List<string> SupportedGenerationMethods { get; set; } = new();
    }

    private sealed class FinalArtifactSet
    {
        public string RagJsonPath { get; set; } = string.Empty;
        public string ZeroShotJsonPath { get; set; } = string.Empty;
        public string CodeBertJsonPath { get; set; } = string.Empty;
        public string ExcelReportPath { get; set; } = string.Empty;
        public string HtmlReportPath { get; set; } = string.Empty;
        public string ApiDiagnosticsJsonPath { get; set; } = string.Empty;
        public string ConsoleLogJsonPath { get; set; } = string.Empty;
    }

    private sealed class ConsoleExecutionLogReport
    {
        public DateTimeOffset GeneratedAtUtc { get; set; }
        public int EntryCount { get; set; }
        public string FullText { get; set; } = string.Empty;
        public List<ConsoleLogEntry> Entries { get; set; } = new();
    }

    private sealed class ConsoleLogEntry
    {
        public long Sequence { get; set; }
        public DateTimeOffset TimestampUtc { get; set; }
        public string Stream { get; set; } = string.Empty;
        public string Message { get; set; } = string.Empty;
        public bool EndsLine { get; set; }
    }

    private sealed class MetricFormulaDescription
    {
        public string Formula { get; set; } = string.Empty;
        public string Description { get; set; } = string.Empty;
    }

    private sealed class ApiDiagnosticsReport
    {
        public DateTimeOffset GeneratedAtUtc { get; set; }
        public string RootFolder { get; set; } = string.Empty;
        public string ModelName { get; set; } = string.Empty;
        public int TotalCalls { get; set; }
        public int SuccessfulCalls { get; set; }
        public int FailedCalls { get; set; }
        public List<RateLimitObservation> RateLimitHeaderObservations { get; set; } = new();
        public List<GeminiApiDiagnostic> Diagnostics { get; set; } = new();
    }

    private sealed class RateLimitObservation
    {
        public DateTimeOffset TimestampUtc { get; set; }
        public string Operation { get; set; } = string.Empty;
        public string Scenario { get; set; } = string.Empty;
        public string ModelName { get; set; } = string.Empty;
        public int? HttpStatusCode { get; set; }
        public Dictionary<string, List<string>> Headers { get; set; } = new(StringComparer.OrdinalIgnoreCase);
    }

    private sealed class GeminiApiDiagnostic
    {
        public DateTimeOffset TimestampUtc { get; set; }
        public string Operation { get; set; } = string.Empty;
        public string Endpoint { get; set; } = string.Empty;
        public string ModelName { get; set; } = string.Empty;
        public string Scenario { get; set; } = string.Empty;
        public int PackageCount { get; set; }
        public int? HttpStatusCode { get; set; }
        public string HttpStatusDescription { get; set; } = string.Empty;
        public bool Success { get; set; }
        public double ElapsedMilliseconds { get; set; }
        public Dictionary<string, List<string>> RateLimitHeaders { get; set; } = new(StringComparer.OrdinalIgnoreCase);
        public Dictionary<string, List<string>> ResponseHeaders { get; set; } = new(StringComparer.OrdinalIgnoreCase);
        public string ResponsePreview { get; set; } = string.Empty;
        public string ErrorMessage { get; set; } = string.Empty;
    }

    private sealed class BatchAuditReport
    {
        public DateTimeOffset GeneratedAtUtc { get; set; }
        public string RootFolder { get; set; } = string.Empty;
        public string ModelName { get; set; } = string.Empty;
        public int ProjectCount { get; set; }
        public int SucceededProjectCount { get; set; }
        public int FailedProjectCount { get; set; }
        public List<ProjectAuditResult> Results { get; set; } = new();
    }

    private sealed class ScenarioJsonReport
    {
        public DateTimeOffset GeneratedAtUtc { get; set; }
        public string RootFolder { get; set; } = string.Empty;
        public string ModelName { get; set; } = string.Empty;
        public AuditScenario Scenario { get; set; }
        public int ProjectCount { get; set; }
        public int SucceededProjectCount { get; set; }
        public int FailedProjectCount { get; set; }
        public int TotalExtractedPackages { get; set; }
        public int TotalVulnerabilityReports { get; set; }
        public int VulnerableFindingCount { get; set; }
        public int GroundedFindingCount { get; set; }
        public Dictionary<string, VulnerabilityFieldDescription> VulnerabilityReportFieldDescriptions { get; set; } = new();
        public Dictionary<string, MetricFormulaDescription> MetricFormulaDescriptions { get; set; } = new();
        public List<ProjectVulnerabilityReport> VulnerabilityReports { get; set; } = new();
        public List<ProjectScenarioJsonReport> Projects { get; set; } = new();
    }

    private sealed class ProjectVulnerabilityReport : VulnerabilityReport
    {
        public string ProjectName { get; set; } = string.Empty;
        public string ProjectKey { get; set; } = string.Empty;
        public string ProjectPath { get; set; } = string.Empty;
    }

    private sealed class ProjectScenarioJsonReport
    {
        public string ProjectName { get; set; } = string.Empty;
        public string ProjectKey { get; set; } = string.Empty;
        public string ProjectPath { get; set; } = string.Empty;
        public int PackageCount { get; set; }
        public List<NuGetPackageReference> ExtractedPackages { get; set; } = new();
        public List<GroundTruthLabel> GroundTruthLabels { get; set; } = new();
        public string SecurityReferenceSource { get; set; } = string.Empty;
        public List<string> RetrievalDiagnostics { get; set; } = new();
        public AuditScenario Scenario { get; set; }
        public string ScenarioStatus { get; set; } = string.Empty;
        public bool ExcludedFromMetrics { get; set; }
        public string MetricExclusionReason { get; set; } = string.Empty;
        public ScenarioAuditResult? ScenarioResult { get; set; }
        public List<VulnerabilityReport> VulnerabilityReports { get; set; } = new();
        public EvaluationMetrics? Metrics { get; set; }
        public List<string> Messages { get; set; } = new();
    }

    private sealed class CodeBertJsonReport
    {
        public DateTimeOffset GeneratedAtUtc { get; set; }
        public string RootFolder { get; set; } = string.Empty;
        public string ModelName { get; set; } = string.Empty;
        public int ProjectCount { get; set; }
        public int TotalRecords { get; set; }
        public int TrainingCount { get; set; }
        public int ValidationCount { get; set; }
        public int TestingCount { get; set; }
        public string SplitStrategy { get; set; } = string.Empty;
        public string AugmentationStrategy { get; set; } = string.Empty;
        public string EvaluationStatus { get; set; } = string.Empty;
        public string EvaluationNote { get; set; } = string.Empty;
        public Dictionary<string, string> DatasetFieldDescriptions { get; set; } = new();
        public List<ProjectCodeBertJsonReport> Projects { get; set; } = new();
    }

    private sealed class ProjectCodeBertJsonReport
    {
        public string ProjectName { get; set; } = string.Empty;
        public string ProjectKey { get; set; } = string.Empty;
        public string ProjectPath { get; set; } = string.Empty;
        public int PackageCount { get; set; }
        public string SecurityReferenceSource { get; set; } = string.Empty;
        public int TotalRecords { get; set; }
        public int TrainingCount { get; set; }
        public int ValidationCount { get; set; }
        public int TestingCount { get; set; }
        public string EvaluationStatus { get; set; } = string.Empty;
        public string EvaluationNote { get; set; } = string.Empty;
        public List<CodeBertDatasetRecord> Records { get; set; } = new();
    }

    private sealed class ProjectAuditResult
    {
        public string ProjectName { get; set; } = string.Empty;
        public string ProjectKey { get; set; } = string.Empty;
        public string ProjectPath { get; set; } = string.Empty;
        public string ModelName { get; set; } = string.Empty;
        public string CheckpointSchemaVersion { get; set; } = string.Empty;
        public int PackageCount { get; set; }
        public bool Success { get; set; }
        public string ErrorMessage { get; set; } = string.Empty;
        public string SecurityReferenceSource { get; set; } = string.Empty;
        public DateTimeOffset StartedAtUtc { get; set; }
        public DateTimeOffset CompletedAtUtc { get; set; }
        public double ElapsedSeconds { get; set; }
        public List<string> RetrievalDiagnostics { get; set; } = new();
        public List<string> Messages { get; set; } = new();
        public List<ScenarioAuditResult> Scenarios { get; set; } = new();
        public List<NuGetPackageReference> ExtractedPackages { get; set; } = new();
        public List<GroundTruthLabel> GroundTruthLabels { get; set; } = new();
        public List<CodeBertDatasetRecord> CodeBertRecords { get; set; } = new();
    }

    private sealed class ScenarioAuditResult
    {
        public AuditScenario Scenario { get; set; }
        public bool Success { get; set; }
        public string Status { get; set; } = "PENDING";
        public string ErrorMessage { get; set; } = string.Empty;
        public bool ExcludedFromMetrics { get; set; }
        public string MetricExclusionReason { get; set; } = string.Empty;
        public int VulnerableCount { get; set; }
        public string AuditJsonPath { get; set; } = string.Empty;
        public DateTimeOffset StartedAtUtc { get; set; }
        public DateTimeOffset CompletedAtUtc { get; set; }
        public double ElapsedSeconds { get; set; }
        public GeminiResponse? Response { get; set; }
        public EvaluationMetrics? Metrics { get; set; }
    }

    private sealed class CapturingConsoleWriter : TextWriter
    {
        private readonly TextWriter innerWriter;
        private readonly string streamName;
        private readonly Encoding encoding;

        public CapturingConsoleWriter(TextWriter innerWriter, string streamName, Encoding encoding)
        {
            this.innerWriter = innerWriter;
            this.streamName = streamName;
            this.encoding = encoding;
        }

        public override Encoding Encoding => encoding;

        public override IFormatProvider FormatProvider => CultureInfo.InvariantCulture;

        public override void Write(string? value)
        {
            innerWriter.Write(value);

            if (value is not null)
            {
                AddConsoleLog(streamName, value, false);
            }
        }

        public override void WriteLine(string? value)
        {
            innerWriter.WriteLine(value);
            AddConsoleLog(streamName, value ?? string.Empty, true);
        }

        public override void Write(char value)
        {
            innerWriter.Write(value);
            AddConsoleLog(streamName, value.ToString(), false);
        }

        public override void WriteLine()
        {
            innerWriter.WriteLine();
            AddConsoleLog(streamName, string.Empty, true);
        }

        public override void Flush()
        {
            innerWriter.Flush();
        }
    }
}
