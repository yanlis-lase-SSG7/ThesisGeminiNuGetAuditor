using System.Collections.Concurrent;
using System.ComponentModel;
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
    private const string CodeBertPythonEnvironmentVariableName = "CODEBERT_PYTHON";
    private const string CodeBertModelEnvironmentVariableName = "CODEBERT_MODEL_PATH";
    private const string CodeBertInferenceScriptName = "codebert_inference.py";
    private const string CheckpointSchemaVersion = "2026-06-27-codebert-real-local-v4";
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
            WriteLine("Starting parallel checkpointed evaluation: RAG-LLM, Zero-Shot, and CodeBERT Python inference.");

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
            WriteLine($"Comprehensive CSV report: {artifactSet.CsvReportPath}");
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

            WriteLine($"[{projectKey}] Found {packageReferences.Count} package(s). Starting strict live GitHub GraphQL retrieval.");

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

            if (!IsLiveSecurityReferenceSuccessful(securityContextResult))
            {
                var message = "Live GitHub GraphQL retrieval failed, so ground truth is unavailable. Project is excluded from all scenario metrics to protect experiment validity.";
                result.ErrorMessage = message;
                result.Messages.Add(message);
                result.Scenarios.Add(CreateRetrievalFailedScenario(AuditScenario.ZeroShot, securityContextResult.Source, message));
                result.Scenarios.Add(CreateRetrievalFailedScenario(AuditScenario.RagLlm, securityContextResult.Source, message));
                result.Scenarios.Add(CreateRetrievalFailedScenario(AuditScenario.CodeBert, securityContextResult.Source, message));
                WriteError($"[{projectKey}] {message}");
                return result;
            }

            var securityContext = securityContextResult.Context;
            var groundTruthLabels = GroundTruthProvider.BuildLabels(packageReferences, securityContext);
            result.GroundTruthLabels = groundTruthLabels.ToList();

            WriteLine($"[{projectKey}] Ground truth prepared from live GitHub GraphQL data. Starting Zero-Shot, RAG-LLM, and CodeBERT preparation.");

            var zeroShotTask = RunGeminiScenarioSafelyAsync(
                projectKey,
                AuditScenario.ZeroShot,
                apiKey,
                modelName,
                geminiSettings,
                packageReferences,
                "[]",
                cancellationToken);

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

            try
            {
                result.CodeBertRecords = await codeBertTask;
                result.Messages.Add($"CodeBERT records prepared: {result.CodeBertRecords.Count}.");

                var codeBertResult = await RunCodeBertScenarioSafelyAsync(
                    projectKey,
                    result.CodeBertRecords,
                    groundTruthLabels,
                    outputDirectory,
                    cancellationToken);
                result.Scenarios.Add(codeBertResult);
                result.CodeBertInputJsonPath = codeBertResult.InputJsonPath;
                result.CodeBertPredictionJsonPath = codeBertResult.PredictionJsonPath;
            }
            catch (Exception ex)
            {
                result.Messages.Add($"CodeBERT dataset preparation failed: {ex.Message}");
                result.Scenarios.Add(CreateFailedCodeBertScenario(ex.Message));
            }

            foreach (var scenarioResult in result.Scenarios)
            {
                if (scenarioResult.Response is null)
                {
                    scenarioResult.Status = scenarioResult.Scenario == AuditScenario.CodeBert ? "CODEBERT_FAILED" : "API_FAILED";
                    scenarioResult.ExcludedFromMetrics = true;
                    scenarioResult.MetricExclusionReason = scenarioResult.Scenario == AuditScenario.CodeBert
                        ? "Prediksi CodeBERT tidak tersedia karena Python inference gagal. Skenario ini tidak dimasukkan ke confusion matrix."
                        : "Prediksi LLM tidak tersedia karena API gagal setelah retry. Tidak ada fallback ke Ground Truth.";
                    result.Messages.Add($"{scenarioResult.Scenario} marked {scenarioResult.Status} and excluded from metrics. {scenarioResult.ErrorMessage}");
                    continue;
                }

                var metrics = ModelEvaluator.Calculate(
                    $"{projectKey}:{GetScenarioDisplayName(scenarioResult.Scenario)}",
                    scenarioResult.Response.VulnerabilityReports,
                    groundTruthLabels);

                scenarioResult.Metrics = metrics;
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

    private static bool IsLiveSecurityReferenceSuccessful(SecurityReferenceProvider.SecurityContextResult result)
    {
        return string.Equals(result.Source, "GitHubGraphQLApi", StringComparison.OrdinalIgnoreCase);
    }

    private static ScenarioAuditResult CreateRetrievalFailedScenario(
        AuditScenario scenario,
        string retrievalSource,
        string message)
    {
        return new ScenarioAuditResult
        {
            Scenario = scenario,
            Status = "RETRIEVAL_FAILED",
            Success = false,
            ExcludedFromMetrics = true,
            MetricExclusionReason = $"{message} RetrievalSource={retrievalSource}.",
            ErrorMessage = message,
            StartedAtUtc = DateTimeOffset.UtcNow,
            CompletedAtUtc = DateTimeOffset.UtcNow
        };
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

    private static async Task<ScenarioAuditResult> RunCodeBertScenarioSafelyAsync(
        string projectKey,
        IReadOnlyCollection<CodeBertDatasetRecord> records,
        IReadOnlyCollection<GroundTruthLabel> groundTruthLabels,
        string outputDirectory,
        CancellationToken cancellationToken)
    {
        var stopwatch = Stopwatch.StartNew();
        var result = new ScenarioAuditResult
        {
            Scenario = AuditScenario.CodeBert,
            StartedAtUtc = DateTimeOffset.UtcNow
        };

        try
        {
            WriteLine($"[{projectKey}] [CodeBERT] Preparing Python inference input.");
            var codeBertDirectory = Path.Combine(outputDirectory, "codebert");
            Directory.CreateDirectory(codeBertDirectory);

            var inputPath = Path.Combine(codeBertDirectory, $"{projectKey}-codebert-input.json");
            var predictionPath = Path.Combine(codeBertDirectory, $"{projectKey}-codebert-predictions.json");
            var input = new CodeBertInferenceInput
            {
                ProjectKey = projectKey,
                GeneratedAtUtc = DateTimeOffset.UtcNow,
                Records = records.ToList(),
                GroundTruthLabels = groundTruthLabels.ToList()
            };

            File.WriteAllText(inputPath, JsonSerializer.Serialize(input, SerializerOptions), Encoding.UTF8);
            result.InputJsonPath = inputPath;
            result.PredictionJsonPath = predictionPath;

            await ExecuteCodeBertPythonAsync(inputPath, predictionPath, cancellationToken);

            var response = ModelEvaluator.LoadCodeBertPredictions(predictionPath);
            result.Response = NormalizeResponse(
                groundTruthLabels.Select(x => new NuGetPackageReference
                {
                    PackageName = x.PackageName,
                    CurrentVersion = x.CurrentVersion
                }).ToList(),
                response);
            result.Status = "SUCCESS";
            result.ExcludedFromMetrics = false;
            result.Success = true;
            result.VulnerableCount = result.Response.VulnerabilityReports.Count(x => x.IsVulnerable);
            WriteLine($"[{projectKey}] [CodeBERT] Finished. Vulnerable detections: {result.VulnerableCount}.");
        }
        catch (Exception ex)
        {
            result.Success = false;
            result.Status = "CODEBERT_FAILED";
            result.ExcludedFromMetrics = true;
            result.MetricExclusionReason = "Prediksi CodeBERT tidak tersedia karena Python inference gagal.";
            result.ErrorMessage = ex.Message;
            WriteError($"[{projectKey}] [CodeBERT] Failed: {ex.Message}");
        }
        finally
        {
            stopwatch.Stop();
            result.CompletedAtUtc = DateTimeOffset.UtcNow;
            result.ElapsedSeconds = stopwatch.Elapsed.TotalSeconds;
        }

        return result;
    }

    private static ScenarioAuditResult CreateFailedCodeBertScenario(string message)
    {
        return new ScenarioAuditResult
        {
            Scenario = AuditScenario.CodeBert,
            Status = "CODEBERT_FAILED",
            Success = false,
            ExcludedFromMetrics = true,
            MetricExclusionReason = "Dataset CodeBERT gagal dibuat sehingga Python inference tidak dijalankan.",
            ErrorMessage = message,
            StartedAtUtc = DateTimeOffset.UtcNow,
            CompletedAtUtc = DateTimeOffset.UtcNow
        };
    }

    private static async Task ExecuteCodeBertPythonAsync(
        string inputPath,
        string outputPath,
        CancellationToken cancellationToken)
    {
        var pythonExecutable = Environment.GetEnvironmentVariable(CodeBertPythonEnvironmentVariableName);
        if (string.IsNullOrWhiteSpace(pythonExecutable))
        {
            pythonExecutable = "python";
        }

        var scriptPath = Path.Combine(GetApplicationRootDirectory(), CodeBertInferenceScriptName);
        if (!File.Exists(scriptPath))
        {
            throw new FileNotFoundException("CodeBERT inference script was not found.", scriptPath);
        }

        var startInfo = new ProcessStartInfo
        {
            FileName = pythonExecutable,
            WorkingDirectory = GetApplicationRootDirectory(),
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
            CreateNoWindow = true
        };
        startInfo.ArgumentList.Add(scriptPath);
        startInfo.ArgumentList.Add("--input");
        startInfo.ArgumentList.Add(inputPath);
        startInfo.ArgumentList.Add("--output");
        startInfo.ArgumentList.Add(outputPath);
        var codeBertModelPath = Environment.GetEnvironmentVariable(CodeBertModelEnvironmentVariableName);
        if (!string.IsNullOrWhiteSpace(codeBertModelPath))
        {
            startInfo.ArgumentList.Add("--model");
            startInfo.ArgumentList.Add(codeBertModelPath);
        }

        var stderrBuilder = new StringBuilder();
        using var process = new Process
        {
            StartInfo = startInfo,
            EnableRaisingEvents = true
        };

        process.OutputDataReceived += (_, args) =>
        {
            if (!string.IsNullOrWhiteSpace(args.Data))
            {
                WriteLine($"[CodeBERT] {args.Data}");
            }
        };

        process.ErrorDataReceived += (_, args) =>
        {
            if (!string.IsNullOrWhiteSpace(args.Data))
            {
                stderrBuilder.AppendLine(args.Data);
                WriteError($"[CodeBERT] {args.Data}");
            }
        };

        var modelLog = string.IsNullOrWhiteSpace(codeBertModelPath)
            ? $"no {CodeBertModelEnvironmentVariableName} configured"
            : $"model \"{codeBertModelPath}\"";
        WriteLine($"[CodeBERT] Executing local Python inference: {pythonExecutable} {CodeBertInferenceScriptName} --input \"{inputPath}\" --output \"{outputPath}\" ({modelLog})");

        try
        {
            if (!process.Start())
            {
                throw new InvalidOperationException("Failed to start CodeBERT Python process.");
            }
        }
        catch (Win32Exception ex)
        {
            throw new InvalidOperationException(
                $"Python executable '{pythonExecutable}' was not found or could not be started. Install Python locally or set the {CodeBertPythonEnvironmentVariableName} environment variable to a valid executable path.",
                ex);
        }

        process.BeginOutputReadLine();
        process.BeginErrorReadLine();

        try
        {
            await Task.Run(process.WaitForExit, cancellationToken);
            process.WaitForExit();
        }
        catch (OperationCanceledException)
        {
            if (!process.HasExited)
            {
                process.Kill(entireProcessTree: true);
            }

            throw;
        }

        if (process.ExitCode != 0)
        {
            throw new InvalidOperationException(
                $"CodeBERT Python process exited with code {process.ExitCode}. stderr: {TruncateForDisplay(stderrBuilder.ToString(), 1000)}");
        }

        if (!File.Exists(outputPath))
        {
            throw new FileNotFoundException("CodeBERT Python process completed but prediction file was not created.", outputPath);
        }

        WriteLine($"[CodeBERT] Python inference completed successfully. Prediction file: {outputPath}");
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
            ModelName = modelName,
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

            var parsed = JsonSerializer.Deserialize<GeminiResponse>(ExtractJsonPayload(json), SerializerOptions);
            if (parsed is not null)
            {
                parsed.ModelName = modelName;
            }

            return parsed;
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
            ModelName = geminiResponse?.ModelName ?? string.Empty,
            InferenceMode = geminiResponse?.InferenceMode ?? string.Empty,
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
            CsvReportPath = Path.Combine(outputDirectory, $"audit-comprehensive-metrics-{timestamp}.csv"),
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
        SaveComprehensiveCsvReport(artifactSet.CsvReportPath, results);
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
        var codeBert = result.Scenarios.FirstOrDefault(x => x.Scenario == AuditScenario.CodeBert);

        if (result.PackageCount == 0 && result.Success && result.ErrorMessage.Length == 0)
        {
            return true;
        }

        return result.ErrorMessage.Length == 0 &&
               result.PackageCount >= 0 &&
               result.CodeBertRecords.Count > 0 &&
               rag is { Success: true, Response: not null } &&
               zeroShot is { Success: true, Response: not null } &&
               codeBert is { Success: true, Response: not null };
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
            .Select(project =>
            {
                var codeBert = project.Scenarios.FirstOrDefault(x => x.Scenario == AuditScenario.CodeBert);
                return new ProjectCodeBertJsonReport
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
                    EvaluationStatus = codeBert?.Status ?? "NOT_RUN",
                    PredictionModelName = GetPredictionModelName(codeBert),
                    InferenceMode = GetInferenceMode(codeBert),
                    IsSyntheticPrediction = IsSyntheticCodeBertScenario(codeBert),
                    EvaluationNote = codeBert?.Success == true
                        ? GetCodeBertEvaluationNote(codeBert)
                        : codeBert?.ErrorMessage ?? "CodeBERT inference was not executed.",
                    InputJsonPath = project.CodeBertInputJsonPath,
                    PredictionJsonPath = project.CodeBertPredictionJsonPath,
                    Predictions = codeBert?.Response?.VulnerabilityReports ?? new List<VulnerabilityReport>(),
                    Metrics = codeBert?.Metrics,
                    Records = project.CodeBertRecords
                };
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
            EvaluationStatus = projectReports.All(x => string.Equals(x.EvaluationStatus, "SUCCESS", StringComparison.OrdinalIgnoreCase))
                ? "SUCCESS"
                : "PARTIAL_OR_FAILED",
            EvaluationNote = "CodeBERT metrics are produced only when codebert_inference.py completes real local inference and writes prediction JSON. If the local model or Python libraries are unavailable, CodeBERT is marked CODEBERT_FAILED and excluded from metrics.",
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

    private static string GetPredictionModelName(ScenarioAuditResult? scenario)
    {
        if (scenario is null)
        {
            return string.Empty;
        }

        return scenario.Response?.ModelName ?? string.Empty;
    }

    private static string GetInferenceMode(ScenarioAuditResult? scenario)
    {
        if (scenario is null)
        {
            return "NOT_RUN";
        }

        if (scenario.Scenario == AuditScenario.CodeBert)
        {
            return string.IsNullOrWhiteSpace(scenario.Response?.InferenceMode)
                ? "PYTHON_BRIDGE"
                : scenario.Response.InferenceMode;
        }

        return "GEMINI_API";
    }

    private static bool IsSyntheticCodeBertScenario(ScenarioAuditResult? scenario)
    {
        return scenario?.Scenario == AuditScenario.CodeBert &&
               (GetPredictionModelName(scenario).Contains("mock", StringComparison.OrdinalIgnoreCase) ||
                GetPredictionModelName(scenario).Contains("synthetic", StringComparison.OrdinalIgnoreCase));
    }

    private static string GetMetricNote(ScenarioAuditResult? scenario)
    {
        if (scenario is null)
        {
            return "Scenario was not run.";
        }

        if (scenario.ExcludedFromMetrics)
        {
            return scenario.MetricExclusionReason;
        }

        if (IsSyntheticCodeBertScenario(scenario))
        {
            return "Synthetic CodeBERT predictions were detected. Do not use this scenario as model-quality evidence.";
        }

        return "Metrics calculated from model predictions and ground truth labels.";
    }

    private static string GetCodeBertEvaluationNote(ScenarioAuditResult? scenario)
    {
        return IsSyntheticCodeBertScenario(scenario)
            ? "Synthetic CodeBERT predictions were detected. Metrics are retained only for traceability and must not be used as model-quality evidence."
            : "Local Python CodeBERT inference completed and metrics were calculated with ModelEvaluator.";
    }

    private static void SaveComprehensiveCsvReport(string outputFilePath, IReadOnlyCollection<ProjectAuditResult> results)
    {
        var builder = new StringBuilder();
        builder.AppendLine("ProjectName,ProjectKey,Scenario,Status,PredictionModelName,InferenceMode,MetricNote,Total,TP,TN,FP,FN,Accuracy,Precision,Recall,F1Score,FalsePositiveRatio");

        foreach (var project in results.OrderBy(x => x.ProjectName, StringComparer.OrdinalIgnoreCase))
        {
            foreach (var scenario in project.Scenarios.OrderBy(x => GetScenarioDisplayName(x.Scenario), StringComparer.OrdinalIgnoreCase))
            {
                var metrics = scenario.Metrics;
                builder.AppendLine(string.Join(
                    ',',
                    Csv(project.ProjectName),
                    Csv(project.ProjectKey),
                    Csv(GetScenarioDisplayName(scenario.Scenario)),
                    Csv(scenario.Status),
                    Csv(GetPredictionModelName(scenario)),
                    Csv(GetInferenceMode(scenario)),
                    Csv(GetMetricNote(scenario)),
                    (metrics?.Total ?? 0).ToString(CultureInfo.InvariantCulture),
                    (metrics?.TruePositive ?? 0).ToString(CultureInfo.InvariantCulture),
                    (metrics?.TrueNegative ?? 0).ToString(CultureInfo.InvariantCulture),
                    (metrics?.FalsePositive ?? 0).ToString(CultureInfo.InvariantCulture),
                    (metrics?.FalseNegative ?? 0).ToString(CultureInfo.InvariantCulture),
                    (metrics?.Accuracy ?? 0d).ToString(CultureInfo.InvariantCulture),
                    (metrics?.Precision ?? 0d).ToString(CultureInfo.InvariantCulture),
                    (metrics?.Recall ?? 0d).ToString(CultureInfo.InvariantCulture),
                    (metrics?.F1Score ?? 0d).ToString(CultureInfo.InvariantCulture),
                    (metrics?.FalsePositiveRatio ?? 0d).ToString(CultureInfo.InvariantCulture)));
            }
        }

        File.WriteAllText(outputFilePath, builder.ToString(), Encoding.UTF8);
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
            ("CodeBertProjectResults", results.Count(x => x.Scenarios.Any(s => s.Scenario == AuditScenario.CodeBert && s.Success)).ToString()),
            ("ApiFailedScenarioResults", results.SelectMany(x => x.Scenarios).Count(s => s.Status == "API_FAILED").ToString()),
            ("MetricExclusionPolicy", "Scenario with API_FAILED, RETRIEVAL_FAILED, or missing prediction is excluded from confusion matrix; no Ground Truth fallback is used."),
            ("GroundTruthPolicy", "A package is labeled vulnerable only when its current version satisfies the advisory vulnerable version range."),
            ("CodeBertRecords", results.Sum(x => x.CodeBertRecords.Count).ToString()),
            ("CodeBertEvaluationPolicy", "CodeBERT prediction metrics require local Python inference with a fine-tuned model configured through CODEBERT_MODEL_PATH. Missing model or libraries mark CodeBERT as CODEBERT_FAILED and exclude it from metrics."),
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
        var headers = new[] { "Metric", "RAG-LLM", "Zero-Shot", "CodeBERT", "Delta (RAG-ZeroShot)", "Delta (RAG-CodeBERT)", "Description" };
        WriteHeaders(sheet, headers);

        var rag = AggregateScenarioMetrics(results, AuditScenario.RagLlm);
        var zeroShot = AggregateScenarioMetrics(results, AuditScenario.ZeroShot);
        var codeBert = AggregateScenarioMetrics(results, AuditScenario.CodeBert);
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
            var codeBertValue = rows[i].Metric switch
            {
                "Accuracy" => codeBert.Accuracy,
                "Precision" => codeBert.Precision,
                "Recall" => codeBert.Recall,
                "F1Score" => codeBert.F1Score,
                "FalsePositiveRatio" => codeBert.FalsePositiveRatio,
                "TruePositive" => codeBert.TruePositive,
                "TrueNegative" => codeBert.TrueNegative,
                "FalsePositive" => codeBert.FalsePositive,
                "FalseNegative" => codeBert.FalseNegative,
                "Total" => codeBert.Total,
                _ => 0d
            };
            sheet.Cell(row, 4).Value = codeBertValue;
            sheet.Cell(row, 5).Value = rows[i].Rag - rows[i].ZeroShot;
            sheet.Cell(row, 6).Value = rows[i].Rag - codeBertValue;
            sheet.Cell(row, 7).Value = rows[i].Description;
        }

        sheet.Range(2, 2, 6, 6).Style.NumberFormat.Format = "0.00%";
        sheet.Column(7).Style.Alignment.WrapText = true;
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
            ("CodeBERT", "Dataset CodeBERT diekspor, lalu codebert_inference.py menjalankan inferensi lokal dengan model fine-tuned dari CODEBERT_MODEL_PATH. Jika model atau library Python belum tersedia, skenario ditandai CODEBERT_FAILED dan tidak masuk metrik."),
            ("Ground Truth Version Range", "Package hanya dianggap vulnerable jika CurrentVersion masuk VulnerableVersionRange. Ini mencegah package patched tetap dihitung sebagai vulnerable hanya karena namanya punya advisory."),
            ("Run Summary", "Ringkasan eksekusi: model, jumlah project, jumlah sukses/gagal, concurrency, dan jumlah record."),
            ("Method Comparison", "Tabel cepat untuk melihat status tiga metode per project: RAG-LLM, Zero-Shot, dan CodeBERT."),
            ("Project Status", "Status per project, termasuk status RAG, Zero-Shot, jumlah record CodeBERT, dan error jika ada."),
            ("Scenario Metrics", "Confusion matrix dan metrik untuk RAG-LLM, Zero-Shot, dan CodeBERT."),
            ("Finding Detail", "Detail package-level: prediksi model, ground truth, CVE, severity, mitigasi, dan reasoning bilingual."),
            ("False Review", "Sheet False Positive Review dan False Negative Review memisahkan error prediksi agar mudah dianalisis."),
            ("Ground Truth", "Label pembanding berasal eksklusif dari GitHub GraphQL API real-time dan evaluasi rentang versi. Ini dasar TP/TN/FP/FN."),
            ("CodeBERT Dataset", "Record dataset yang diekspor: original, semantic_version_normalization, dan safe_dummy_dependency."),
            ("Retrieval Diagnostics", "Jejak sumber advisory yang dipakai untuk tiap project."),
            ("Field Descriptions", "Kamus field JSON dan Excel agar pembaca memahami arti setiap kolom temuan."),
            ("Metric Definitions", "Rumus Accuracy, Precision, Recall, F1, False Positive Ratio, dan confusion matrix."),
            ("JSON Reports", "audit-rag-llm*.json dan audit-zero-shot*.json berisi report LLM; audit-codebert*.json berisi dataset, prediksi CodeBERT bridge, metadata inference, dan metrik; api-diagnostics*.json berisi kesehatan API."),
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
            "CodeBertStatus", "CodeBertAccuracy", "CodeBertPrecision", "CodeBertRecall", "CodeBertF1",
            "CodeBertPredictionModel", "CodeBertInferenceMode", "CodeBertRecords", "CodeBertTraining", "CodeBertValidation", "CodeBertTesting", "CodeBertPredictionJsonPath"
        };
        WriteHeaders(sheet, headers);

        var row = 2;
        foreach (var project in results)
        {
            var rag = project.Scenarios.FirstOrDefault(x => x.Scenario == AuditScenario.RagLlm);
            var zeroShot = project.Scenarios.FirstOrDefault(x => x.Scenario == AuditScenario.ZeroShot);
            var codeBert = project.Scenarios.FirstOrDefault(x => x.Scenario == AuditScenario.CodeBert);
            var codeBertRecords = project.CodeBertRecords;

            sheet.Cell(row, 1).Value = project.ProjectName;
            sheet.Cell(row, 2).Value = project.ProjectKey;
            sheet.Cell(row, 3).Value = project.PackageCount;
            sheet.Cell(row, 4).Value = rag?.Status ?? "NOT_RUN";
            WriteMetricCells(sheet, row, 5, rag?.Metrics);
            sheet.Cell(row, 9).Value = zeroShot?.Status ?? "NOT_RUN";
            WriteMetricCells(sheet, row, 10, zeroShot?.Metrics);
            sheet.Cell(row, 14).Value = codeBert?.Status ?? "NOT_RUN";
            WriteMetricCells(sheet, row, 15, codeBert?.Metrics);
            sheet.Cell(row, 19).Value = GetPredictionModelName(codeBert);
            sheet.Cell(row, 20).Value = GetInferenceMode(codeBert);
            sheet.Cell(row, 21).Value = codeBertRecords.Count;
            sheet.Cell(row, 22).Value = codeBertRecords.Count(x => x.Split == "training");
            sheet.Cell(row, 23).Value = codeBertRecords.Count(x => x.Split == "validation");
            sheet.Cell(row, 24).Value = codeBertRecords.Count(x => x.Split == "testing");
            sheet.Cell(row, 25).Value = project.CodeBertPredictionJsonPath;
            row++;
        }

        if (row > 2)
        {
            sheet.Range(2, 5, row - 1, 8).Style.NumberFormat.Format = "0.00%";
            sheet.Range(2, 10, row - 1, 13).Style.NumberFormat.Format = "0.00%";
            sheet.Range(2, 15, row - 1, 18).Style.NumberFormat.Format = "0.00%";
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
            "CodeBertStatus", "CodeBertSuccess", "CodeBertExcludedFromMetrics", "CodeBertMetricExclusionReason",
            "CodeBertPredictionModel", "CodeBertInferenceMode", "CodeBertRecords", "ElapsedSeconds", "ErrorMessage"
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
            var codeBert = project.Scenarios.FirstOrDefault(x => x.Scenario == AuditScenario.CodeBert);
            sheet.Cell(row, 7).Value = rag?.Status ?? "NOT_RUN";
            sheet.Cell(row, 8).Value = rag?.Success ?? false;
            sheet.Cell(row, 9).Value = rag?.ExcludedFromMetrics ?? true;
            sheet.Cell(row, 10).Value = rag?.MetricExclusionReason ?? string.Empty;
            sheet.Cell(row, 11).Value = zeroShot?.Status ?? "NOT_RUN";
            sheet.Cell(row, 12).Value = zeroShot?.Success ?? false;
            sheet.Cell(row, 13).Value = zeroShot?.ExcludedFromMetrics ?? true;
            sheet.Cell(row, 14).Value = zeroShot?.MetricExclusionReason ?? string.Empty;
            sheet.Cell(row, 15).Value = codeBert?.Status ?? "NOT_RUN";
            sheet.Cell(row, 16).Value = codeBert?.Success ?? false;
            sheet.Cell(row, 17).Value = codeBert?.ExcludedFromMetrics ?? true;
            sheet.Cell(row, 18).Value = codeBert?.MetricExclusionReason ?? string.Empty;
            sheet.Cell(row, 19).Value = GetPredictionModelName(codeBert);
            sheet.Cell(row, 20).Value = GetInferenceMode(codeBert);
            sheet.Cell(row, 21).Value = project.CodeBertRecords.Count;
            sheet.Cell(row, 22).Value = project.ElapsedSeconds;
            sheet.Cell(row, 23).Value = project.ErrorMessage;
            row++;
        }

        FormatUsedRangeAsTable(sheet, headers.Length);
    }

    private static void WriteScenarioMetricsSheet(XLWorkbook workbook, IReadOnlyCollection<ProjectAuditResult> results)
    {
        var sheet = workbook.Worksheets.Add("Scenario Metrics");
        var headers = new[]
        {
            "ProjectName", "ProjectKey", "Scenario", "Status", "PredictionModelName", "InferenceMode", "MetricNote",
            "Total", "TP", "TN", "FP", "FN", "Accuracy", "Precision", "Recall", "F1Score", "FalsePositiveRatio"
        };
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
                sheet.Cell(row, 4).Value = scenario.Status;
                sheet.Cell(row, 5).Value = GetPredictionModelName(scenario);
                sheet.Cell(row, 6).Value = GetInferenceMode(scenario);
                sheet.Cell(row, 7).Value = GetMetricNote(scenario);
                sheet.Cell(row, 8).Value = metrics.Total;
                sheet.Cell(row, 9).Value = metrics.TruePositive;
                sheet.Cell(row, 10).Value = metrics.TrueNegative;
                sheet.Cell(row, 11).Value = metrics.FalsePositive;
                sheet.Cell(row, 12).Value = metrics.FalseNegative;
                sheet.Cell(row, 13).Value = metrics.Accuracy;
                sheet.Cell(row, 14).Value = metrics.Precision;
                sheet.Cell(row, 15).Value = metrics.Recall;
                sheet.Cell(row, 16).Value = metrics.F1Score;
                sheet.Cell(row, 17).Value = metrics.FalsePositiveRatio;
                row++;
            }
        }

        if (row > 2)
        {
            sheet.Range(2, 13, row - 1, 17).Style.NumberFormat.Format = "0.00%";
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
        var headers = new[]
        {
            "ProjectName", "ProjectKey", "Status", "DatasetRecords", "Training", "Validation", "Testing",
            "TP", "TN", "FP", "FN", "Accuracy", "Precision", "Recall", "F1Score",
            "PredictionModelName", "InferenceMode", "InputJsonPath", "PredictionJsonPath", "Explanation"
        };
        WriteHeaders(sheet, headers);

        var row = 2;
        foreach (var project in results)
        {
            var codeBert = project.Scenarios.FirstOrDefault(x => x.Scenario == AuditScenario.CodeBert);
            var metrics = codeBert?.Metrics;
            sheet.Cell(row, 1).Value = project.ProjectName;
            sheet.Cell(row, 2).Value = project.ProjectKey;
            sheet.Cell(row, 3).Value = codeBert?.Status ?? "NOT_RUN";
            sheet.Cell(row, 4).Value = project.CodeBertRecords.Count;
            sheet.Cell(row, 5).Value = project.CodeBertRecords.Count(x => x.Split == "training");
            sheet.Cell(row, 6).Value = project.CodeBertRecords.Count(x => x.Split == "validation");
            sheet.Cell(row, 7).Value = project.CodeBertRecords.Count(x => x.Split == "testing");
            sheet.Cell(row, 8).Value = metrics?.TruePositive ?? 0;
            sheet.Cell(row, 9).Value = metrics?.TrueNegative ?? 0;
            sheet.Cell(row, 10).Value = metrics?.FalsePositive ?? 0;
            sheet.Cell(row, 11).Value = metrics?.FalseNegative ?? 0;
            sheet.Cell(row, 12).Value = metrics?.Accuracy ?? 0d;
            sheet.Cell(row, 13).Value = metrics?.Precision ?? 0d;
            sheet.Cell(row, 14).Value = metrics?.Recall ?? 0d;
            sheet.Cell(row, 15).Value = metrics?.F1Score ?? 0d;
            sheet.Cell(row, 16).Value = GetPredictionModelName(codeBert);
            sheet.Cell(row, 17).Value = GetInferenceMode(codeBert);
            sheet.Cell(row, 18).Value = project.CodeBertInputJsonPath;
            sheet.Cell(row, 19).Value = project.CodeBertPredictionJsonPath;
            sheet.Cell(row, 20).Value = codeBert?.Success == true
                ? GetCodeBertEvaluationNote(codeBert)
                : codeBert?.ErrorMessage ?? "CodeBERT inference was not executed.";
            row++;
        }

        if (row > 2)
        {
            sheet.Range(2, 12, row - 1, 15).Style.NumberFormat.Format = "0.00%";
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
        var codeBertResults = results.SelectMany(p => p.Scenarios.Where(s => s.Scenario == AuditScenario.CodeBert).Select(s => (Project: p, Scenario: s))).ToList();
        var allFindings = results
            .SelectMany(project => project.Scenarios.SelectMany(scenario =>
                scenario.Response?.VulnerabilityReports.Select(report => (Project: project, Scenario: scenario, Report: report))
                ?? Enumerable.Empty<(ProjectAuditResult Project, ScenarioAuditResult Scenario, VulnerabilityReport Report)>()))
            .ToList();
        var allMetricRecords = results
            .SelectMany(project => project.Scenarios.SelectMany(scenario =>
                scenario.Metrics?.Records.Select(record => (Project: project, Scenario: scenario, Record: record))
                ?? Enumerable.Empty<(ProjectAuditResult Project, ScenarioAuditResult Scenario, EvaluationRecord Record)>()))
            .ToList();
        var vulnerableTruthCount = results.Sum(x => x.GroundTruthLabels.Count(g => g.IsVulnerable));
        var falsePositiveCount = allMetricRecords.Count(x => x.Record.MatchResult == "False Positive");
        var falseNegativeCount = allMetricRecords.Count(x => x.Record.MatchResult == "False Negative");

        var builder = new StringBuilder();
        builder.AppendLine("<!doctype html>");
        builder.AppendLine("<html lang=\"en\"><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">");
        builder.AppendLine("<title>GeminiNuGetAuditor Interactive Audit Report / Laporan Audit Interaktif</title>");
        builder.AppendLine("""
<style>
:root{--bg:#f5f7fb;--panel:#ffffff;--ink:#172033;--muted:#657089;--line:#dbe3ef;--brand:#1d4ed8;--brand2:#0f766e;--bert:#7c3aed;--good:#065f46;--good-bg:#d1fae5;--good-dark:#bbf7d0;--warn:#92400e;--bad:#991b1b;--tp:#047857;--tn:#2563eb;--fp:#ea580c;--fn:#dc2626}
*{box-sizing:border-box} body{margin:0;background:var(--bg);color:var(--ink);font-family:Segoe UI,Roboto,Arial,sans-serif;line-height:1.45}
header{background:linear-gradient(135deg,#0f172a,#1d4ed8 58%,#0f766e);color:white;padding:34px 42px}
header h1{margin:0 0 8px;font-size:30px;letter-spacing:0} header p{margin:0;color:#dbeafe;max-width:1100px}header .id,header .id-block{color:var(--good-dark)!important}.hero-meta{display:flex;flex-wrap:wrap;gap:8px;margin-top:14px}.hero-meta span{border:1px solid rgba(255,255,255,.34);background:rgba(255,255,255,.14);border-radius:999px;padding:6px 10px;font-size:12px;color:#f8fafc}
main{padding:24px 42px 48px}.grid{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:14px}.card{background:var(--panel);border:1px solid var(--line);border-radius:8px;padding:16px;box-shadow:0 8px 24px rgba(15,23,42,.06)}
.metric .label{color:var(--muted);font-size:12px;text-transform:uppercase;letter-spacing:.04em}.metric .value{font-size:28px;font-weight:700;margin-top:4px}.metric .sub{color:var(--muted);font-size:12px;margin-top:4px}
section{margin-top:18px}.section-title{display:flex;align-items:end;justify-content:space-between;gap:12px;margin:24px 0 10px}h2{font-size:20px;margin:0}.hint{color:var(--muted);font-size:13px}.mono{font-family:Consolas,Menlo,monospace}.id{color:var(--brand2);font-style:italic;font-weight:650}.id-block{display:block;color:var(--brand2);font-style:italic;font-weight:550;margin-top:2px}.id-soft{color:#0f766e;font-style:italic}
table{width:100%;border-collapse:collapse;background:var(--panel);border:1px solid var(--line);border-radius:8px;overflow:hidden}th,td{padding:10px 12px;border-bottom:1px solid var(--line);text-align:left;vertical-align:top;font-size:13px}th{background:#eef4ff;color:#24324b;position:sticky;top:0;z-index:1}tr:hover td{background:#f8fbff}
.pill{display:inline-flex;align-items:center;border-radius:999px;padding:3px 9px;font-size:12px;font-weight:700}.good{background:var(--good-bg);color:var(--good)}.bad{background:#fee2e2;color:var(--bad)}.warn{background:#fef3c7;color:var(--warn)}.neutral{background:#e5e7eb;color:#374151}
.toolbar{display:flex;gap:10px;align-items:center;flex-wrap:wrap;background:#eef4ff;border:1px solid var(--line);border-radius:8px;padding:10px}.toolbar input,.toolbar select{min-width:190px;padding:10px 12px;border:1px solid var(--line);border-radius:8px;background:white}.toolbar input{min-width:300px}.toolbar label{font-size:13px;color:#24324b;display:flex;gap:6px;align-items:center}.toolbar button{padding:10px 12px;border:1px solid var(--line);border-radius:8px;background:white;cursor:pointer}
.tabs{display:flex;gap:8px;flex-wrap:wrap;margin-top:10px}.tab{border:1px solid var(--line);background:white;border-radius:999px;padding:8px 12px;cursor:pointer}.tab.active{background:var(--brand);color:white;border-color:var(--brand)}.tab.active .id{color:#dbeafe}
.panel{display:none}.panel.active{display:block}.two{display:grid;grid-template-columns:1fr 1fr;gap:14px}.three{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:14px}.files a{display:block;color:var(--brand);text-decoration:none;margin:6px 0}.files a:hover{text-decoration:underline}
.summary-card{border-left:4px solid var(--brand)}.summary-card.codebert{border-left-color:var(--bert)}.summary-card.zero{border-left-color:var(--brand2)}.score{font-size:22px;font-weight:700}.bar-label{display:flex;justify-content:space-between;gap:8px;margin-top:8px}.bar-track{height:12px;background:#e5e7eb;border-radius:999px;overflow:hidden}.bar-fill{height:12px}.detail{max-width:520px}.row-hidden{display:none!important}
.flow{display:grid;grid-template-columns:repeat(5,minmax(0,1fr));gap:10px}.flow-step{border:1px solid var(--line);border-radius:8px;padding:12px;background:#f8fbff;position:relative}.flow-step strong{display:block}.flow-step .num{display:inline-flex;width:24px;height:24px;align-items:center;justify-content:center;border-radius:999px;background:var(--brand);color:white;font-weight:700;margin-bottom:8px}.flow-step:not(:last-child)::after{content:"";position:absolute;right:-10px;top:50%;width:10px;border-top:2px solid #93c5fd}
.chart-grid{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:14px}.donut-card{display:flex;gap:14px;align-items:center}.donut{width:112px;height:112px;border-radius:50%;display:grid;place-items:center;flex:0 0 auto}.donut span{width:72px;height:72px;border-radius:50%;background:white;display:grid;place-items:center;text-align:center;font-size:12px;font-weight:700}.legend{display:flex;flex-wrap:wrap;gap:8px;margin-top:10px}.legend span{font-size:12px;color:var(--muted)}.legend i{display:inline-block;width:10px;height:10px;border-radius:2px;margin-right:4px}.stack{height:16px;background:#e5e7eb;border-radius:999px;overflow:hidden;display:flex}.stack span{display:block;height:16px}.mini-kpis{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:10px}.mini-kpi{border:1px solid var(--line);border-radius:8px;padding:12px;background:#f8fbff}.mini-kpi strong{font-size:20px}.small-table td,.small-table th{font-size:12px}.codebert-note{border:1px solid #c4b5fd;background:#f5f3ff;color:#4c1d95;border-radius:8px;padding:10px;margin-top:10px}
details{background:#f8fbff;border:1px solid var(--line);border-radius:8px;padding:10px}summary{cursor:pointer;font-weight:600}
@media(max-width:1100px){main,header{padding-left:18px;padding-right:18px}.grid,.two,.three,.flow,.chart-grid,.mini-kpis{grid-template-columns:1fr}.toolbar input,.toolbar select{min-width:100%;width:100%}.flow-step:not(:last-child)::after{display:none}}
</style>
""");
        builder.AppendLine("</head><body>");
        builder.AppendLine("<header>");
        builder.AppendLine("<h1>GeminiNuGetAuditor Interactive Audit Report</h1>");
        builder.AppendLine("<p class=\"id-block\" style=\"color:#dbeafe\">Laporan Audit Interaktif GeminiNuGetAuditor</p>");
        builder.AppendLine($"<p>Audit root <span class=\"id\">Folder audit</span>: {Html(rootFolder)} &nbsp; | &nbsp; Model <span class=\"id\">Model</span>: <strong>{Html(modelName)}</strong> &nbsp; | &nbsp; Generated <span class=\"id\">Dibuat</span>: {Html(DateTimeOffset.UtcNow.ToString("O"))}</p>");
        builder.AppendLine("<div class=\"hero-meta\">");
        builder.AppendLine($"<span>{results.Count} project(s) <span class=\"id\">proyek</span></span><span>{results.Sum(x => x.PackageCount)} package(s) <span class=\"id\">paket</span></span><span>{vulnerableTruthCount} ground-truth vulnerable <span class=\"id\">rentan menurut ground truth</span></span><span>{results.SelectMany(x => x.Scenarios).Count(x => x.Status == "API_FAILED")} API failed scenario(s) <span class=\"id\">skenario API gagal</span></span>");
        builder.AppendLine("</div>");
        builder.AppendLine("</header><main>");

        builder.AppendLine("<section class=\"grid\">");
        AppendMetricCard(builder, "Projects", "Proyek", results.Count.ToString(CultureInfo.InvariantCulture), $"{results.Count(IsProjectFullySuccessfulForResume)} complete", $"{results.Count(IsProjectFullySuccessfulForResume)} selesai");
        AppendMetricCard(builder, "Packages", "Paket", results.Sum(x => x.PackageCount).ToString(CultureInfo.InvariantCulture), $"{vulnerableTruthCount} vulnerable by ground truth", $"{vulnerableTruthCount} rentan menurut ground truth");
        AppendMetricCard(builder, "RAG Findings", "Temuan RAG", ragResults.Sum(x => x.Scenario.Response?.VulnerabilityReports.Count(r => r.IsVulnerable) ?? 0).ToString(CultureInfo.InvariantCulture), "grounded Gemini scenario", "skenario Gemini dengan konteks");
        AppendMetricCard(builder, "Zero-Shot Findings", "Temuan Zero-Shot", zeroShotResults.Sum(x => x.Scenario.Response?.VulnerabilityReports.Count(r => r.IsVulnerable) ?? 0).ToString(CultureInfo.InvariantCulture), "no retrieval context", "tanpa konteks retrieval");
        AppendMetricCard(builder, "CodeBERT Findings", "Temuan CodeBERT", codeBertResults.Sum(x => x.Scenario.Response?.VulnerabilityReports.Count(r => r.IsVulnerable) ?? 0).ToString(CultureInfo.InvariantCulture), $"{results.Sum(x => x.CodeBertRecords.Count)} dataset records", $"{results.Sum(x => x.CodeBertRecords.Count)} record dataset");
        AppendMetricCard(builder, "False Positives", "Positif Palsu", falsePositiveCount.ToString(CultureInfo.InvariantCulture), "all evaluated scenarios", "semua skenario");
        AppendMetricCard(builder, "False Negatives", "Negatif Palsu", falseNegativeCount.ToString(CultureInfo.InvariantCulture), "all evaluated scenarios", "semua skenario");
        AppendMetricCard(builder, "API Failed", "API Gagal", results.SelectMany(x => x.Scenarios).Count(x => x.Status == "API_FAILED").ToString(CultureInfo.InvariantCulture), "Gemini scenario failures", "kegagalan skenario Gemini");
        builder.AppendLine("</section>");

        builder.AppendLine("""
<section class="card">
<div class="section-title"><h2>How to read<span class="id-block">Cara membaca</span></h2><span class="hint">Two LLM audit scenarios and one CodeBERT bridge scenario.<span class="id-block">Dua skenario audit LLM dan satu skenario bridge CodeBERT.</span></span></div>
<div class="two">
<div><strong>RAG-LLM</strong><p>Gemini receives package references plus retrieved security context.<span class="id-block">Gemini menerima daftar package plus konteks keamanan hasil retrieval.</span></p></div>
<div><strong>Zero-Shot</strong><p>Gemini receives only package references.<span class="id-block">Gemini hanya menerima daftar package tanpa konteks advisory.</span></p></div>
<div><strong>CodeBERT</strong><p>The app exports labeled rows, executes codebert_inference.py, and evaluates predictions with the same confusion matrix only when local CodeBERT inference succeeds.<span class="id-block">Aplikasi mengekspor dataset berlabel, menjalankan codebert_inference.py, lalu mengevaluasi prediksi dengan confusion matrix yang sama hanya ketika inferensi CodeBERT lokal berhasil.</span></p></div>
<div><strong>Ground Truth<span class="id-block">Label Acuan</span></strong><p>Labels come exclusively from live GitHub GraphQL advisory retrieval and version-range evaluation.<span class="id-block">Label berasal secara eksklusif dari retrieval advisory GitHub GraphQL real-time dan evaluasi rentang versi sebagai dasar TP/TN/FP/FN.</span></p></div>
</div>
</section>
""");

        AppendExecutiveSummary(builder, results);
        AppendExperimentFlow(builder, results);

        builder.AppendLine("<section><div class=\"section-title\"><h2>Interactive Dashboard<span class=\"id-block\">Dashboard Interaktif</span></h2><span class=\"hint\">Search and filter without opening Excel.<span class=\"id-block\">Cari dan filter tanpa membuka Excel.</span></span></div>");
        builder.AppendLine("""
<div class="toolbar">
<input id="q" placeholder="Search / Cari project, package, CVE, severity, mitigation...">
<select id="scenarioFilter"><option value="">All scenarios - Semua skenario</option><option>RAG-LLM</option><option>Zero-Shot</option><option>CodeBERT</option></select>
<select id="statusFilter"><option value="">All statuses - Semua status</option><option>SUCCESS</option><option>VULNERABLE</option><option>SAFE</option><option>False Positive</option><option>False Negative</option><option>GROUNDED</option><option>UNGROUNDED</option></select>
<label><input type="checkbox" id="vulnerableOnly"> Vulnerable only <span class="id">Hanya rentan</span></label>
<button id="clearFilters" type="button">Clear <span class="id">Bersihkan</span></button>
</div>
<div class="tabs">
<button class="tab active" data-tab="overview">Overview <span class="id">Ringkasan</span></button>
<button class="tab" data-tab="projects">Projects <span class="id">Proyek</span></button>
<button class="tab" data-tab="findings">Findings <span class="id">Temuan</span></button>
<button class="tab" data-tab="errors">Error Review <span class="id">Ulasan Error</span></button>
<button class="tab" data-tab="groundtruth">Ground Truth <span class="id">Label Acuan</span></button>
<button class="tab" data-tab="artifacts">Artifacts <span class="id">Artefak</span></button>
</div>
""");
        builder.AppendLine("<div id=\"overview\" class=\"panel active\">");
        AppendScenarioSummaryCards(builder, results);
        AppendRetrievalCoverageChart(builder, results);
        AppendComparisonChart(builder, results);
        AppendConfusionDonutChart(builder, results);
        AppendPredictionOutcomeChart(builder, results);
        AppendConfusionMatrixTable(builder, results);
        AppendHotspotTable(builder, allFindings, allMetricRecords);
        builder.AppendLine("</div><div id=\"projects\" class=\"panel\">");
        AppendProjectTable(builder, results);
        builder.AppendLine("</div><div id=\"findings\" class=\"panel\">");
        AppendFindingTable(builder, allFindings);
        builder.AppendLine("</div><div id=\"errors\" class=\"panel\">");
        AppendErrorReviewTable(builder, results);
        builder.AppendLine("</div><div id=\"groundtruth\" class=\"panel\">");
        AppendGroundTruthTable(builder, results);
        builder.AppendLine("</div><div id=\"artifacts\" class=\"panel card files\">");
        AppendArtifactLinks(builder, artifactSet);
        builder.AppendLine("</div></section>");
        builder.AppendLine("""
<script>
const tabs=[...document.querySelectorAll('.tab')],panels=[...document.querySelectorAll('.panel')],q=document.getElementById('q'),scenarioFilter=document.getElementById('scenarioFilter'),statusFilter=document.getElementById('statusFilter'),vulnerableOnly=document.getElementById('vulnerableOnly'),clearFilters=document.getElementById('clearFilters');
tabs.forEach(t=>t.addEventListener('click',()=>{tabs.forEach(x=>x.classList.remove('active'));panels.forEach(p=>p.classList.remove('active'));t.classList.add('active');document.getElementById(t.dataset.tab).classList.add('active');filter()}));
[q,scenarioFilter,statusFilter,vulnerableOnly].forEach(x=>x.addEventListener('input',filter));
clearFilters.addEventListener('click',()=>{q.value='';scenarioFilter.value='';statusFilter.value='';vulnerableOnly.checked=false;filter()});
function filter(){
 const term=q.value.toLowerCase(), scenario=scenarioFilter.value, status=statusFilter.value;
 document.querySelectorAll('.panel.active tbody tr').forEach(r=>{
  const text=r.innerText.toLowerCase(), rowScenario=r.dataset.scenario||'', rowStatus=r.dataset.status||'', rowVuln=r.dataset.vulnerable||'';
  const okText=!term||text.includes(term), okScenario=!scenario||rowScenario===scenario||rowScenario==='All', okStatus=!status||rowStatus.includes(status), okVuln=!vulnerableOnly.checked||rowVuln==='true';
  r.classList.toggle('row-hidden',!(okText&&okScenario&&okStatus&&okVuln));
 });
}
</script>
""");
        builder.AppendLine("</main></body></html>");
        File.WriteAllText(outputFilePath, builder.ToString(), Encoding.UTF8);
    }

    private static void AppendMetricCard(StringBuilder builder, string labelEnglish, string labelIndonesia, string value, string subtitleEnglish, string subtitleIndonesia)
    {
        builder.AppendLine($"<div class=\"card metric\"><div class=\"label\">{Html(labelEnglish)}<span class=\"id-block\">{Html(labelIndonesia)}</span></div><div class=\"value\">{Html(value)}</div><div class=\"sub\">{Html(subtitleEnglish)}<span class=\"id-block\">{Html(subtitleIndonesia)}</span></div></div>");
    }

    private static void AppendExecutiveSummary(StringBuilder builder, IReadOnlyCollection<ProjectAuditResult> results)
    {
        var scenarioMetrics = new[]
        {
            (Scenario: AuditScenario.RagLlm, Metrics: AggregateScenarioMetrics(results, AuditScenario.RagLlm)),
            (Scenario: AuditScenario.ZeroShot, Metrics: AggregateScenarioMetrics(results, AuditScenario.ZeroShot)),
            (Scenario: AuditScenario.CodeBert, Metrics: AggregateScenarioMetrics(results, AuditScenario.CodeBert))
        };
        var best = scenarioMetrics.OrderByDescending(x => x.Metrics.F1Score).First();
        var apiFailed = results.SelectMany(x => x.Scenarios).Count(x => x.Status == "API_FAILED");
        var codeBertScenarios = results.SelectMany(x => x.Scenarios).Where(x => x.Scenario == AuditScenario.CodeBert).ToList();
        var codeBertSucceeded = codeBertScenarios.Count(x => x.Success);
        var codeBertFailed = codeBertScenarios.Count(x => !x.Success);

        builder.AppendLine("<section class=\"card\">");
        builder.AppendLine("<div class=\"section-title\"><h2>Executive Summary<span class=\"id-block\">Ringkasan Eksekutif</span></h2><span class=\"hint\">Generated automatically from this run.<span class=\"id-block\">Dibuat otomatis dari hasil run ini.</span></span></div>");
        builder.AppendLine("<div class=\"three\">");
        builder.AppendLine("<div><strong>Best F1<span class=\"id-block\">F1 Terbaik</span></strong>");
        builder.AppendLine($"<p>{Html(GetScenarioDisplayName(best.Scenario))}: {best.Metrics.F1Score:P1}. Accuracy <span class=\"id\">Akurasi</span> {best.Metrics.Accuracy:P1}, Recall {best.Metrics.Recall:P1}.</p></div>");
        builder.AppendLine("<div><strong>Execution Health<span class=\"id-block\">Kesehatan Eksekusi</span></strong>");
        builder.AppendLine($"<p>{results.Count(IsProjectFullySuccessfulForResume)} / {results.Count} project complete. API failed scenarios: {apiFailed}.<span class=\"id-block\">{results.Count(IsProjectFullySuccessfulForResume)} / {results.Count} proyek selesai. Skenario API gagal: {apiFailed}.</span></p></div>");
        builder.AppendLine("<div><strong>CodeBERT Status<span class=\"id-block\">Status CodeBERT</span></strong>");
        builder.AppendLine(codeBertSucceeded > 0
            ? $"<p>{codeBertSucceeded} CodeBERT local inference result(s) were evaluated; {codeBertFailed} failed or excluded.<span class=\"id-block\">{codeBertSucceeded} hasil inferensi CodeBERT lokal dievaluasi; {codeBertFailed} gagal atau dikeluarkan.</span></p>"
            : $"<p>No CodeBERT metrics were counted because local inference did not complete. Configure {Html(CodeBertModelEnvironmentVariableName)} to enable this scenario.<span class=\"id-block\">Tidak ada metrik CodeBERT yang dihitung karena inferensi lokal tidak selesai. Atur {Html(CodeBertModelEnvironmentVariableName)} untuk mengaktifkan skenario ini.</span></p>");
        builder.AppendLine("</div></div>");

        if (results.Count < 1000)
        {
            builder.AppendLine($"<p class=\"hint\">Dataset scope note: this run contains {results.Count} project file(s), so use it as a sample validation run before the full 1,000-file audit.<span class=\"id-block\">Catatan cakupan dataset: run ini berisi {results.Count} file project, sehingga cocok sebagai validasi sample sebelum audit penuh 1.000 file.</span></p>");
        }

        builder.AppendLine("</section>");
    }

    private static void AppendExperimentFlow(StringBuilder builder, IReadOnlyCollection<ProjectAuditResult> results)
    {
        var packageCount = results.Sum(x => x.PackageCount);
        var retrievalSuccess = results.Count(x => string.Equals(x.SecurityReferenceSource, "GitHubGraphQLApi", StringComparison.OrdinalIgnoreCase));
        var retrievalFailed = results.Count - retrievalSuccess;
        var llmSuccess = results.SelectMany(x => x.Scenarios).Count(x => (x.Scenario is AuditScenario.RagLlm or AuditScenario.ZeroShot) && x.Success);
        var codeBertSuccess = results.SelectMany(x => x.Scenarios).Count(x => x.Scenario == AuditScenario.CodeBert && x.Success);

        builder.AppendLine("<section class=\"card\">");
        builder.AppendLine("<div class=\"section-title\"><h2>Experiment Flow<span class=\"id-block\">Alur Eksperimen</span></h2><span class=\"hint\">Live-only ground truth, local inference, unified metrics.<span class=\"id-block\">Ground truth live-only, inferensi lokal, metrik terpadu.</span></span></div>");
        builder.AppendLine("<div class=\"flow\">");
        AppendFlowStep(builder, 1, "Scan", "Pindai", $"{results.Count} project", $"{results.Count} proyek");
        AppendFlowStep(builder, 2, "Extract", "Ekstraksi", $"{packageCount} packages", $"{packageCount} paket");
        AppendFlowStep(builder, 3, "Live Retrieval", "Retrieval Live", $"{retrievalSuccess} ok / {retrievalFailed} failed", $"{retrievalSuccess} sukses / {retrievalFailed} gagal");
        AppendFlowStep(builder, 4, "Inference", "Inferensi", $"{llmSuccess} Gemini scenarios, {codeBertSuccess} CodeBERT", $"{llmSuccess} skenario Gemini, {codeBertSuccess} CodeBERT");
        AppendFlowStep(builder, 5, "Evaluate", "Evaluasi", "TP/TN/FP/FN", "Confusion matrix terpadu");
        builder.AppendLine("</div></section>");
    }

    private static void AppendFlowStep(StringBuilder builder, int number, string labelEnglish, string labelIndonesia, string valueEnglish, string valueIndonesia)
    {
        builder.AppendLine("<div class=\"flow-step\">");
        builder.AppendLine($"<span class=\"num\">{number}</span>");
        builder.AppendLine($"<strong>{Html(labelEnglish)}<span class=\"id-block\">{Html(labelIndonesia)}</span></strong>");
        builder.AppendLine($"<p class=\"hint\">{Html(valueEnglish)}<span class=\"id-block\">{Html(valueIndonesia)}</span></p>");
        builder.AppendLine("</div>");
    }

    private static void AppendRetrievalCoverageChart(StringBuilder builder, IReadOnlyCollection<ProjectAuditResult> results)
    {
        var totalProjects = results.Count;
        var liveProjects = results.Count(x => string.Equals(x.SecurityReferenceSource, "GitHubGraphQLApi", StringComparison.OrdinalIgnoreCase));
        var failedProjects = Math.Max(0, totalProjects - liveProjects);
        var groundTruthRows = results.Sum(x => x.GroundTruthLabels.Count);
        var vulnerableRows = results.Sum(x => x.GroundTruthLabels.Count(y => y.IsVulnerable));
        var advisoryCount = results
            .SelectMany(x => x.GroundTruthLabels)
            .Select(x => x.AdvisoryId)
            .Where(x => !string.IsNullOrWhiteSpace(x))
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .Count();

        builder.AppendLine("<section class=\"card\"><div class=\"section-title\"><h2>Retrieval Coverage<span class=\"id-block\">Cakupan Retrieval</span></h2><span class=\"hint\">GitHub GraphQL API is the sole source of ground truth.<span class=\"id-block\">GitHub GraphQL API adalah satu-satunya sumber ground truth.</span></span></div>");
        builder.AppendLine("<div class=\"mini-kpis\">");
        AppendMiniKpi(builder, "Live projects", "Proyek live", liveProjects.ToString(CultureInfo.InvariantCulture), $"{PercentText(Ratio(liveProjects, totalProjects))} coverage");
        AppendMiniKpi(builder, "Failed retrieval", "Retrieval gagal", failedProjects.ToString(CultureInfo.InvariantCulture), "excluded from metrics");
        AppendMiniKpi(builder, "Ground-truth rows", "Baris ground truth", groundTruthRows.ToString(CultureInfo.InvariantCulture), $"{vulnerableRows} vulnerable");
        AppendMiniKpi(builder, "Unique advisories", "Advisory unik", advisoryCount.ToString(CultureInfo.InvariantCulture), "live GraphQL result");
        builder.AppendLine("</div>");
        builder.AppendLine("<div style=\"margin-top:14px\">");
        builder.AppendLine("<div class=\"hint bar-label\"><span>Project retrieval status / Status retrieval proyek</span><span>" + Html($"{liveProjects}/{totalProjects}") + "</span></div>");
        builder.AppendLine("<div class=\"stack\">");
        builder.AppendLine($"<span style=\"width:{CssPercent(Ratio(liveProjects, totalProjects))};background:var(--good)\"></span>");
        builder.AppendLine($"<span style=\"width:{CssPercent(Ratio(failedProjects, totalProjects))};background:var(--bad)\"></span>");
        builder.AppendLine("</div>");
        builder.AppendLine("<div class=\"legend\"><span><i style=\"background:var(--good)\"></i>Live GitHub GraphQL</span><span><i style=\"background:var(--bad)\"></i>Retrieval failed / excluded</span></div>");
        builder.AppendLine("</div></section>");
    }

    private static void AppendMiniKpi(StringBuilder builder, string labelEnglish, string labelIndonesia, string value, string hint)
    {
        builder.AppendLine("<div class=\"mini-kpi\">");
        builder.AppendLine($"<span class=\"hint\">{Html(labelEnglish)}<span class=\"id-block\">{Html(labelIndonesia)}</span></span>");
        builder.AppendLine($"<strong>{Html(value)}</strong>");
        builder.AppendLine($"<div class=\"hint\">{Html(hint)}</div>");
        builder.AppendLine("</div>");
    }

    private static void AppendScenarioSummaryCards(StringBuilder builder, IReadOnlyCollection<ProjectAuditResult> results)
    {
        var scenarios = new[]
        {
            AuditScenario.RagLlm,
            AuditScenario.ZeroShot,
            AuditScenario.CodeBert
        };

        builder.AppendLine("<section><div class=\"section-title\"><h2>Scenario Scorecards / Kartu Skor Skenario</h2><span class=\"hint\">Aggregate model quality and execution mode. / Ringkasan kualitas model dan mode eksekusi.</span></div><div class=\"three\">");
        foreach (var scenario in scenarios)
        {
            var metrics = AggregateScenarioMetrics(results, scenario);
            var scenarioResults = results.SelectMany(x => x.Scenarios.Where(s => s.Scenario == scenario)).ToList();
            var firstScenario = scenarioResults.FirstOrDefault();
            var className = scenario switch
            {
                AuditScenario.ZeroShot => "summary-card zero",
                AuditScenario.CodeBert => "summary-card codebert",
                _ => "summary-card"
            };

            builder.AppendLine($"<div class=\"card {className}\">");
            builder.AppendLine($"<div class=\"label\">{Html(GetScenarioDisplayName(scenario))}</div>");
            builder.AppendLine($"<div class=\"score\">F1 {metrics.F1Score:P1}</div>");
            builder.AppendLine($"<div class=\"hint\">Accuracy/Akurasi {metrics.Accuracy:P1} | Precision/Presisi {metrics.Precision:P1} | Recall {metrics.Recall:P1}</div>");
            builder.AppendLine($"<div style=\"margin-top:10px\">{StatusPill(scenarioResults.All(x => x.Status == "SUCCESS") ? "SUCCESS" : "PARTIAL")}</div>");
            builder.AppendLine($"<p class=\"hint\">Mode / Mode: {Html(GetInferenceMode(firstScenario))}<br>Model / Model: {Html(GetPredictionModelName(firstScenario))}<br>Total evaluated / Total dievaluasi: {metrics.Total}</p>");
            builder.AppendLine("</div>");
        }
        builder.AppendLine("</div></section>");
    }

    private static void AppendConfusionMatrixTable(StringBuilder builder, IReadOnlyCollection<ProjectAuditResult> results)
    {
        builder.AppendLine("<section><div class=\"section-title\"><h2>Confusion Matrix / Matriks Kebingungan</h2><span class=\"hint\">TP/TN/FP/FN aggregated per scenario. / TP/TN/FP/FN agregat per skenario.</span></div>");
        builder.AppendLine("<table><thead><tr><th>Scenario / Skenario</th><th>Total</th><th>TP</th><th>TN</th><th>FP</th><th>FN</th><th>Accuracy / Akurasi</th><th>Precision / Presisi</th><th>Recall</th><th>F1</th><th>Note / Catatan</th></tr></thead><tbody>");
        foreach (var scenario in new[] { AuditScenario.RagLlm, AuditScenario.ZeroShot, AuditScenario.CodeBert })
        {
            var metrics = AggregateScenarioMetrics(results, scenario);
            var firstScenario = results.SelectMany(x => x.Scenarios).FirstOrDefault(x => x.Scenario == scenario);
            builder.AppendLine($"<tr data-scenario=\"{Html(GetScenarioDisplayName(scenario))}\" data-status=\"{Html(firstScenario?.Status ?? "NOT_RUN")}\" data-vulnerable=\"false\">");
            builder.AppendLine($"<td>{Html(GetScenarioDisplayName(scenario))}</td><td>{metrics.Total}</td><td>{metrics.TruePositive}</td><td>{metrics.TrueNegative}</td><td>{metrics.FalsePositive}</td><td>{metrics.FalseNegative}</td>");
            builder.AppendLine($"<td>{metrics.Accuracy:P1}</td><td>{metrics.Precision:P1}</td><td>{metrics.Recall:P1}</td><td>{metrics.F1Score:P1}</td><td>{Html(GetMetricNote(firstScenario))}</td>");
            builder.AppendLine("</tr>");
        }
        builder.AppendLine("</tbody></table></section>");
    }

    private static void AppendHotspotTable(
        StringBuilder builder,
        IReadOnlyCollection<(ProjectAuditResult Project, ScenarioAuditResult Scenario, VulnerabilityReport Report)> findings,
        IReadOnlyCollection<(ProjectAuditResult Project, ScenarioAuditResult Scenario, EvaluationRecord Record)> metricRecords)
    {
        var vulnerableHotspots = findings
            .Where(x => x.Report.IsVulnerable)
            .GroupBy(x => x.Report.PackageName, StringComparer.OrdinalIgnoreCase)
            .Select(x => new
            {
                PackageName = x.Key,
                Count = x.Count(),
                Scenarios = string.Join(", ", x.Select(y => GetScenarioDisplayName(y.Scenario.Scenario)).Distinct().OrderBy(y => y)),
                Versions = string.Join(", ", x.Select(y => y.Report.CurrentVersion).Where(y => !string.IsNullOrWhiteSpace(y)).Distinct().Take(4))
            })
            .OrderByDescending(x => x.Count)
            .ThenBy(x => x.PackageName)
            .Take(12)
            .ToList();

        var errorHotspots = metricRecords
            .Where(x => x.Record.MatchResult is "False Positive" or "False Negative")
            .GroupBy(x => x.Record.PackageName, StringComparer.OrdinalIgnoreCase)
            .Select(x => new
            {
                PackageName = x.Key,
                Count = x.Count(),
                Errors = string.Join(", ", x.Select(y => y.Record.MatchResult).Distinct().OrderBy(y => y)),
                Scenarios = string.Join(", ", x.Select(y => GetScenarioDisplayName(y.Scenario.Scenario)).Distinct().OrderBy(y => y))
            })
            .OrderByDescending(x => x.Count)
            .ThenBy(x => x.PackageName)
            .Take(12)
            .ToList();

        builder.AppendLine("<section><div class=\"section-title\"><h2>Hotspots / Titik Perhatian</h2><span class=\"hint\">Packages most often flagged or misclassified. / Package yang paling sering ditandai atau salah klasifikasi.</span></div><div class=\"two\">");
        builder.AppendLine("<div><h2>Vulnerable Findings / Temuan Rentan</h2><table><thead><tr><th>Package / Paket</th><th>Count / Jumlah</th><th>Scenarios / Skenario</th><th>Versions / Versi</th></tr></thead><tbody>");
        foreach (var item in vulnerableHotspots)
        {
            builder.AppendLine($"<tr data-scenario=\"All\" data-status=\"VULNERABLE\" data-vulnerable=\"true\"><td>{Html(item.PackageName)}</td><td>{item.Count}</td><td>{Html(item.Scenarios)}</td><td>{Html(item.Versions)}</td></tr>");
        }
        builder.AppendLine("</tbody></table></div>");

        builder.AppendLine("<div><h2>Error Hotspots / Titik Error</h2><table><thead><tr><th>Package / Paket</th><th>Error Count / Jumlah Error</th><th>Error Types / Jenis Error</th><th>Scenarios / Skenario</th></tr></thead><tbody>");
        foreach (var item in errorHotspots)
        {
            builder.AppendLine($"<tr data-scenario=\"All\" data-status=\"{Html(item.Errors)}\" data-vulnerable=\"false\"><td>{Html(item.PackageName)}</td><td>{item.Count}</td><td>{Html(item.Errors)}</td><td>{Html(item.Scenarios)}</td></tr>");
        }
        builder.AppendLine("</tbody></table></div></div></section>");
    }

    private static void AppendProjectTable(StringBuilder builder, IReadOnlyCollection<ProjectAuditResult> results)
    {
        builder.AppendLine("<table><thead><tr><th>Project / Proyek</th><th>Packages / Paket</th><th>RAG</th><th>Zero-Shot</th><th>CodeBERT</th><th>Reference / Referensi</th><th>Elapsed / Durasi</th></tr></thead><tbody>");
        foreach (var project in results.OrderBy(x => x.ProjectName, StringComparer.OrdinalIgnoreCase))
        {
            var rag = project.Scenarios.FirstOrDefault(x => x.Scenario == AuditScenario.RagLlm);
            var zero = project.Scenarios.FirstOrDefault(x => x.Scenario == AuditScenario.ZeroShot);
            var codeBert = project.Scenarios.FirstOrDefault(x => x.Scenario == AuditScenario.CodeBert);
            var statuses = string.Join(" ", project.Scenarios.Select(x => x.Status));
            builder.AppendLine($"<tr data-scenario=\"All\" data-status=\"{Html(statuses)}\" data-vulnerable=\"{project.GroundTruthLabels.Any(x => x.IsVulnerable).ToString().ToLowerInvariant()}\">");
            builder.AppendLine($"<td><strong>{Html(project.ProjectName)}</strong><br><span class=\"hint\">{Html(project.ProjectKey)}</span></td>");
            builder.AppendLine($"<td>{project.PackageCount}</td>");
            builder.AppendLine($"<td>{StatusPill(rag?.Status ?? "NOT_RUN")}<br>{MetricMini(rag?.Metrics)}</td>");
            builder.AppendLine($"<td>{StatusPill(zero?.Status ?? "NOT_RUN")}<br>{MetricMini(zero?.Metrics)}</td>");
            builder.AppendLine($"<td>{StatusPill(codeBert?.Status ?? "NOT_RUN")}<br>{MetricMini(codeBert?.Metrics)}<br>{Html(GetInferenceMode(codeBert))}<br><span class=\"hint\">{Html(GetPredictionModelName(codeBert))}</span><br>{project.CodeBertRecords.Count} records</td>");
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
        var codeBert = AggregateScenarioMetrics(results, AuditScenario.CodeBert);
        builder.AppendLine("<section class=\"card\"><div class=\"section-title\"><h2>RAG-LLM vs Zero-Shot vs CodeBERT</h2><span class=\"hint\">Aggregate metrics across all evaluated packages. / Metrik agregat untuk semua package yang dievaluasi.</span></div>");
        builder.AppendLine("<div class=\"two\">");
        AppendBarGroup(builder, "Accuracy", rag.Accuracy, zero.Accuracy, codeBert.Accuracy);
        AppendBarGroup(builder, "Precision", rag.Precision, zero.Precision, codeBert.Precision);
        AppendBarGroup(builder, "Recall", rag.Recall, zero.Recall, codeBert.Recall);
        AppendBarGroup(builder, "F1Score", rag.F1Score, zero.F1Score, codeBert.F1Score);
        builder.AppendLine("</div></section>");
    }

    private static void AppendConfusionDonutChart(StringBuilder builder, IReadOnlyCollection<ProjectAuditResult> results)
    {
        builder.AppendLine("<section><div class=\"section-title\"><h2>Confusion Composition<span class=\"id-block\">Komposisi Confusion Matrix</span></h2><span class=\"hint\">TP/TN/FP/FN proportion per scenario.<span class=\"id-block\">Proporsi TP/TN/FP/FN per skenario.</span></span></div>");
        builder.AppendLine("<div class=\"chart-grid\">");
        foreach (var scenario in new[] { AuditScenario.RagLlm, AuditScenario.ZeroShot, AuditScenario.CodeBert })
        {
            var metrics = AggregateScenarioMetrics(results, scenario);
            builder.AppendLine("<div class=\"card donut-card\">");
            builder.AppendLine($"<div class=\"donut\" style=\"{BuildDonutStyle(metrics)}\"><span>F1<br>{metrics.F1Score:P1}</span></div>");
            builder.AppendLine("<div>");
            builder.AppendLine($"<strong>{Html(GetScenarioDisplayName(scenario))}</strong>");
            builder.AppendLine($"<p class=\"hint\">Total {metrics.Total}<br>TP {metrics.TruePositive} | TN {metrics.TrueNegative}<br>FP {metrics.FalsePositive} | FN {metrics.FalseNegative}</p>");
            builder.AppendLine("<div class=\"legend\"><span><i style=\"background:var(--tp)\"></i>TP</span><span><i style=\"background:var(--tn)\"></i>TN</span><span><i style=\"background:var(--fp)\"></i>FP</span><span><i style=\"background:var(--fn)\"></i>FN</span></div>");
            builder.AppendLine("</div></div>");
        }
        builder.AppendLine("</div></section>");
    }

    private static void AppendPredictionOutcomeChart(StringBuilder builder, IReadOnlyCollection<ProjectAuditResult> results)
    {
        builder.AppendLine("<section class=\"card\"><div class=\"section-title\"><h2>Prediction Outcomes<span class=\"id-block\">Outcome Prediksi</span></h2><span class=\"hint\">Stacked view of correct and incorrect classifications.<span class=\"id-block\">Tampilan bertumpuk klasifikasi benar dan salah.</span></span></div>");
        builder.AppendLine("<table class=\"small-table\"><thead><tr><th>Scenario / Skenario</th><th>Outcome Bar / Grafik Outcome</th><th>TP</th><th>TN</th><th>FP</th><th>FN</th><th>Total</th></tr></thead><tbody>");
        foreach (var scenario in new[] { AuditScenario.RagLlm, AuditScenario.ZeroShot, AuditScenario.CodeBert })
        {
            var metrics = AggregateScenarioMetrics(results, scenario);
            builder.AppendLine($"<tr data-scenario=\"{Html(GetScenarioDisplayName(scenario))}\" data-status=\"All\" data-vulnerable=\"false\">");
            builder.AppendLine($"<td>{Html(GetScenarioDisplayName(scenario))}</td><td><div class=\"stack\">");
            AppendStackSegment(builder, metrics.TruePositive, metrics.Total, "var(--tp)");
            AppendStackSegment(builder, metrics.TrueNegative, metrics.Total, "var(--tn)");
            AppendStackSegment(builder, metrics.FalsePositive, metrics.Total, "var(--fp)");
            AppendStackSegment(builder, metrics.FalseNegative, metrics.Total, "var(--fn)");
            builder.AppendLine("</div></td>");
            builder.AppendLine($"<td>{metrics.TruePositive}</td><td>{metrics.TrueNegative}</td><td>{metrics.FalsePositive}</td><td>{metrics.FalseNegative}</td><td>{metrics.Total}</td>");
            builder.AppendLine("</tr>");
        }
        builder.AppendLine("</tbody></table>");
        builder.AppendLine("<div class=\"legend\"><span><i style=\"background:var(--tp)\"></i>True Positive</span><span><i style=\"background:var(--tn)\"></i>True Negative</span><span><i style=\"background:var(--fp)\"></i>False Positive</span><span><i style=\"background:var(--fn)\"></i>False Negative</span></div>");
        builder.AppendLine("</section>");
    }

    private static string BuildDonutStyle(EvaluationMetrics metrics)
    {
        if (metrics.Total <= 0)
        {
            return "background:#e5e7eb";
        }

        var tp = Ratio(metrics.TruePositive, metrics.Total) * 100d;
        var tn = tp + Ratio(metrics.TrueNegative, metrics.Total) * 100d;
        var fp = tn + Ratio(metrics.FalsePositive, metrics.Total) * 100d;
        var fn = 100d;
        return string.Create(
            CultureInfo.InvariantCulture,
            $"background:conic-gradient(var(--tp) 0 {tp:0.##}%,var(--tn) {tp:0.##}% {tn:0.##}%,var(--fp) {tn:0.##}% {fp:0.##}%,var(--fn) {fp:0.##}% {fn:0.##}%)");
    }

    private static void AppendStackSegment(StringBuilder builder, int count, int total, string color)
    {
        if (count <= 0 || total <= 0)
        {
            return;
        }

        builder.AppendLine($"<span style=\"width:{CssPercent(Ratio(count, total))};background:{Html(color)}\"></span>");
    }

    private static void AppendBarGroup(StringBuilder builder, string label, double rag, double zero, double codeBert)
    {
        builder.AppendLine("<div>");
        builder.AppendLine($"<strong>{Html(label)}</strong>");
        AppendBar(builder, "RAG-LLM", rag, "#1d4ed8");
        AppendBar(builder, "Zero-Shot", zero, "#0f766e");
        AppendBar(builder, "CodeBERT", codeBert, "#7c3aed");
        builder.AppendLine("</div>");
    }

    private static void AppendBar(StringBuilder builder, string label, double value, string color)
    {
        var pct = Math.Clamp(value, 0d, 1d) * 100d;
        builder.AppendLine($"<div class=\"hint bar-label\"><span>{Html(label)}</span><span>{pct:0.0}%</span></div>");
        builder.AppendLine($"<div class=\"bar-track\"><div class=\"bar-fill\" style=\"width:{pct:0.##}%;background:{color}\"></div></div>");
    }

    private static void AppendFindingTable(
        StringBuilder builder,
        IReadOnlyCollection<(ProjectAuditResult Project, ScenarioAuditResult Scenario, VulnerabilityReport Report)> findings)
    {
        builder.AppendLine("<table><thead><tr><th>Project / Proyek</th><th>Scenario / Skenario</th><th>Package / Paket</th><th>Version / Versi</th><th>Vulnerable / Rentan</th><th>CVE</th><th>Severity / Tingkat</th><th>Grounded / Berbasis Referensi</th><th>Mitigation / Mitigasi</th></tr></thead><tbody>");
        foreach (var item in findings.OrderByDescending(x => x.Report.IsVulnerable).ThenBy(x => x.Project.ProjectName).ThenBy(x => x.Report.PackageName))
        {
            var scenarioName = GetScenarioDisplayName(item.Scenario.Scenario);
            var status = item.Report.IsVulnerable ? "VULNERABLE" : "SAFE";
            builder.AppendLine($"<tr data-scenario=\"{Html(scenarioName)}\" data-status=\"{Html(status)} {(item.Report.IsGroundedInReference ? "GROUNDED" : "UNGROUNDED")}\" data-vulnerable=\"{item.Report.IsVulnerable.ToString().ToLowerInvariant()}\">");
            builder.AppendLine($"<td>{Html(item.Project.ProjectName)}</td>");
            builder.AppendLine($"<td>{Html(scenarioName)}</td>");
            builder.AppendLine($"<td>{Html(item.Report.PackageName)}</td>");
            builder.AppendLine($"<td>{Html(item.Report.CurrentVersion)}</td>");
            builder.AppendLine($"<td>{StatusPill(item.Report.IsVulnerable ? "VULNERABLE" : "SAFE")}</td>");
            builder.AppendLine($"<td>{Html(item.Report.CVE_ID)}</td>");
            builder.AppendLine($"<td>{Html(item.Report.Severity)}</td>");
            builder.AppendLine($"<td>{StatusPill(item.Report.IsGroundedInReference ? "GROUNDED" : "UNGROUNDED")}</td>");
            var mitigation = item.Report.MitigationPlanIndonesia;
            var reasoning = item.Report.ReasoningTraceIndonesia;
            if (IsSyntheticCodeBertScenario(item.Scenario))
            {
                mitigation = "Output sintetis CodeBERT terdeteksi. Baris ini hanya dipertahankan untuk traceability dan tidak dipakai sebagai bukti kualitas model.";
                reasoning = "Jalankan ulang dengan model lokal melalui CODEBERT_MODEL_PATH untuk menghasilkan prediksi CodeBERT real.";
            }
            builder.AppendLine($"<td class=\"detail\"><details><summary>{Html(TruncateForDisplay(mitigation, 120))}</summary><p>{Html(mitigation)}</p><p class=\"hint\">{Html(reasoning)}</p></details></td>");
            builder.AppendLine("</tr>");
        }
        builder.AppendLine("</tbody></table>");
    }

    private static void AppendErrorReviewTable(StringBuilder builder, IReadOnlyCollection<ProjectAuditResult> results)
    {
        builder.AppendLine("<table><thead><tr><th>Project / Proyek</th><th>Scenario / Skenario</th><th>Package / Paket</th><th>Version / Versi</th><th>Error</th><th>CVE</th><th>Range / Rentang</th><th>Version Evaluation / Evaluasi Versi</th><th>Review Hint / Petunjuk Review</th></tr></thead><tbody>");
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
                    var scenarioName = GetScenarioDisplayName(scenario.Scenario);
                    builder.AppendLine($"<tr data-scenario=\"{Html(scenarioName)}\" data-status=\"{Html(record.MatchResult)}\" data-vulnerable=\"{record.PredictedVulnerable.ToString().ToLowerInvariant()}\">");
                    builder.AppendLine($"<td>{Html(project.ProjectName)}</td>");
                    builder.AppendLine($"<td>{Html(scenarioName)}</td>");
                    builder.AppendLine($"<td>{Html(record.PackageName)}</td>");
                    builder.AppendLine($"<td>{Html(record.CurrentVersion)}</td>");
                    builder.AppendLine($"<td>{StatusPill(record.MatchResult)}</td>");
                    builder.AppendLine($"<td>{Html(record.CVE_ID)}</td>");
                    builder.AppendLine($"<td>{Html(groundTruth?.VulnerableVersionRange)}</td>");
                    builder.AppendLine($"<td>{Html(groundTruth?.VersionRangeEvaluation)}</td>");
                    builder.AppendLine($"<td>{Html(record.MatchResult == "False Positive" ? "Check hallucination or missing advisory range. / Cek kemungkinan halusinasi atau rentang advisory yang hilang." : "Check conservative prompt/reference interpretation. / Cek apakah prompt atau referensi terlalu konservatif.")}</td>");
                    builder.AppendLine("</tr>");
                }
            }
        }
        builder.AppendLine("</tbody></table>");
    }

    private static void AppendGroundTruthTable(StringBuilder builder, IReadOnlyCollection<ProjectAuditResult> results)
    {
        builder.AppendLine("<table><thead><tr><th>Project / Proyek</th><th>Package / Paket</th><th>Version / Versi</th><th>Ground Truth / Label Acuan</th><th>CVE</th><th>Severity / Tingkat</th><th>Advisory</th><th>Vulnerable Range / Rentang Rentan</th><th>Patched Version / Versi Patch</th><th>Version Evaluation / Evaluasi Versi</th></tr></thead><tbody>");
        foreach (var item in results.SelectMany(project => project.GroundTruthLabels.Select(label => (Project: project, Label: label))).OrderByDescending(x => x.Label.IsVulnerable).ThenBy(x => x.Project.ProjectName).ThenBy(x => x.Label.PackageName))
        {
            var status = item.Label.IsVulnerable ? "VULNERABLE" : "SAFE";
            builder.AppendLine($"<tr data-scenario=\"All\" data-status=\"{Html(status)}\" data-vulnerable=\"{item.Label.IsVulnerable.ToString().ToLowerInvariant()}\">");
            builder.AppendLine($"<td>{Html(item.Project.ProjectName)}</td><td>{Html(item.Label.PackageName)}</td><td>{Html(item.Label.CurrentVersion)}</td><td>{StatusPill(status)}</td>");
            builder.AppendLine($"<td>{Html(item.Label.CVE_ID)}</td><td>{Html(item.Label.Severity)}</td><td>{Html(item.Label.AdvisoryId)}</td><td>{Html(item.Label.VulnerableVersionRange)}</td><td>{Html(item.Label.FirstPatchedVersion)}</td><td>{Html(item.Label.VersionRangeEvaluation)}</td>");
            builder.AppendLine("</tr>");
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
            ("Comprehensive Metrics CSV", artifactSet.CsvReportPath),
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
            "API_FAILED" or "CODEBERT_FAILED" or "NOT_EXPORTED" or "VULNERABLE" or "False Positive" or "False Negative" => "bad",
            "NOT_RUN" or "UNGROUNDED" => "warn",
            _ => "neutral"
        };
        return $"<span class=\"pill {css}\">{Html(status)}</span>";
    }

    private static double Ratio(int numerator, int denominator)
    {
        return denominator > 0 ? (double)numerator / denominator : 0d;
    }

    private static string CssPercent(double ratio)
    {
        return $"{Math.Clamp(ratio, 0d, 1d) * 100d:0.##}%".Replace(',', '.');
    }

    private static string PercentText(double ratio)
    {
        return ratio.ToString("P1", CultureInfo.InvariantCulture);
    }

    private static string Html(string? value)
    {
        return WebUtility.HtmlEncode(value ?? string.Empty);
    }

    private static string Csv(string? value)
    {
        var safe = value ?? string.Empty;
        return safe.Contains(',') || safe.Contains('"') || safe.Contains('\n') || safe.Contains('\r')
            ? $"\"{safe.Replace("\"", "\"\"", StringComparison.Ordinal)}\""
            : safe;
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
        public string CsvReportPath { get; set; } = string.Empty;
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
        public string InferencePolicy { get; set; } = "CodeBERT metrics are emitted only from real local Python inference. Synthetic predictions are not generated by the shipped script.";
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
        public string PredictionModelName { get; set; } = string.Empty;
        public string InferenceMode { get; set; } = string.Empty;
        public bool IsSyntheticPrediction { get; set; }
        public string EvaluationNote { get; set; } = string.Empty;
        public string InputJsonPath { get; set; } = string.Empty;
        public string PredictionJsonPath { get; set; } = string.Empty;
        public List<VulnerabilityReport> Predictions { get; set; } = new();
        public EvaluationMetrics? Metrics { get; set; }
        public List<CodeBertDatasetRecord> Records { get; set; } = new();
    }

    private sealed class ProjectAuditResult
    {
        public string ProjectName { get; set; } = string.Empty;
        public string ProjectKey { get; set; } = string.Empty;
        public string ProjectPath { get; set; } = string.Empty;
        public string ModelName { get; set; } = string.Empty;
        public string CheckpointSchemaVersion { get; set; } = string.Empty;
        public string CodeBertInputJsonPath { get; set; } = string.Empty;
        public string CodeBertPredictionJsonPath { get; set; } = string.Empty;
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
        public string InputJsonPath { get; set; } = string.Empty;
        public string PredictionJsonPath { get; set; } = string.Empty;
        public GeminiResponse? Response { get; set; }
        public EvaluationMetrics? Metrics { get; set; }
    }

    private sealed class CodeBertInferenceInput
    {
        public string ProjectKey { get; set; } = string.Empty;
        public DateTimeOffset GeneratedAtUtc { get; set; }
        public List<CodeBertDatasetRecord> Records { get; set; } = new();
        public List<GroundTruthLabel> GroundTruthLabels { get; set; } = new();
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
