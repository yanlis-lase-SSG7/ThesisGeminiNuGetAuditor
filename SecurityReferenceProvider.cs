using System.Collections.Concurrent;
using System.Net;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;

namespace GeminiNuGetAuditor;

public static class SecurityReferenceProvider
{
    private const string GitHubTokenEnvironmentVariableName = "GITHUB_TOKEN";
    private const int GitHubRequestTimeoutSeconds = 30;
    private const int GitHubMaxAttempts = 3;
    private const int GitHubMaxPagesPerPackage = 10;

    private static readonly ConcurrentDictionary<string, Lazy<Task<GitHubPackageQueryResult>>> PackageQueryCache = new(StringComparer.OrdinalIgnoreCase);

    private static readonly JsonDocumentOptions InputJsonOptions = new()
    {
        CommentHandling = JsonCommentHandling.Skip,
        AllowTrailingCommas = true
    };

    private static readonly JsonSerializerOptions SerializerOptions = new()
    {
        WriteIndented = true
    };

    public static string GetSecurityContext(List<string> packages)
    {
        return GetSecurityContextWithDiagnostics(packages).Context;
    }

    public static async Task<string> GetSecurityContextAsync(List<string> packages, CancellationToken cancellationToken = default)
    {
        var result = await GetSecurityContextWithDiagnosticsAsync(packages, cancellationToken);
        return result.Context;
    }

    public static SecurityContextResult GetSecurityContextWithDiagnostics(List<string> packages)
    {
        return GetSecurityContextWithDiagnosticsAsync(packages).GetAwaiter().GetResult();
    }

    public static async Task<SecurityContextResult> GetSecurityContextWithDiagnosticsAsync(
        List<string> packages,
        CancellationToken cancellationToken = default)
    {
        if (packages is null || packages.Count == 0)
        {
            const string message = "No package input. Retrieval skipped.";
            Console.WriteLine($"[Retrieval] Source=None. {message}");
            return new SecurityContextResult
            {
                Context = "[]",
                Source = "None",
                Diagnostics = new List<string> { message }
            };
        }

        var packageSet = new HashSet<string>(
            packages.Where(x => !string.IsNullOrWhiteSpace(x)).Select(x => x.Trim()),
            StringComparer.OrdinalIgnoreCase);

        if (packageSet.Count == 0)
        {
            const string message = "Package input contains only empty names. Retrieval skipped.";
            Console.WriteLine($"[Retrieval] Source=None. {message}");
            return new SecurityContextResult
            {
                Context = "[]",
                Source = "None",
                Diagnostics = new List<string> { message }
            };
        }

        var settings = GetSecurityReferenceSettings();
        var diagnostics = new List<string>
        {
            "Strict real-time retrieval enabled. GitHub GraphQL API is the sole source of truth for vulnerability advisories."
        };

        var githubResult = await TryGetSecurityContextFromGitHubApiAsync(packageSet, settings, cancellationToken);
        diagnostics.AddRange(githubResult.Diagnostics);

        if (!githubResult.AccessSucceeded)
        {
            var message = $"GitHub GraphQL API retrieval failed. Returning empty live context. Reason: {githubResult.ErrorMessage}";
            diagnostics.Add(message);
            Console.WriteLine($"[Retrieval] {message}");

            return new SecurityContextResult
            {
                Context = "[]",
                Source = "GitHubGraphQLApiFailed",
                Diagnostics = diagnostics
            };
        }

        if (githubResult.MatchedCount == 0)
        {
            const string message = "GitHub GraphQL API returned no advisory entries for the requested NuGet packages. Returning empty live context.";
            diagnostics.Add(message);
            Console.WriteLine($"[Retrieval] {message}");
        }
        else
        {
            var message = $"Security reference source selected: GitHubGraphQLApi. Matched advisory entries: {githubResult.MatchedCount}.";
            diagnostics.Add(message);
            Console.WriteLine($"[Retrieval] {message}");
        }

        return new SecurityContextResult
        {
            Context = githubResult.Context,
            Source = "GitHubGraphQLApi",
            Diagnostics = diagnostics
        };
    }

    private static async Task<GitHubSecurityContextResult> TryGetSecurityContextFromGitHubApiAsync(
        HashSet<string> packageSet,
        SecurityReferenceSettings settings,
        CancellationToken cancellationToken)
    {
        var diagnostics = new List<string>();
        var githubToken = ResolveGitHubToken(settings);

        if (string.IsNullOrWhiteSpace(githubToken))
        {
            return new GitHubSecurityContextResult
            {
                AccessSucceeded = false,
                Context = "[]",
                ErrorMessage = $"GitHub token is empty. Set env var '{GitHubTokenEnvironmentVariableName}' or fill 'SecurityReference:GitHubToken'.",
                Diagnostics = diagnostics
            };
        }

        if (string.IsNullOrWhiteSpace(settings.GitHubGraphQlUrl))
        {
            return new GitHubSecurityContextResult
            {
                AccessSucceeded = false,
                Context = "[]",
                ErrorMessage = "GitHub GraphQL URL is empty.",
                Diagnostics = diagnostics
            };
        }

        try
        {
            using var httpClient = new HttpClient
            {
                Timeout = TimeSpan.FromSeconds(GitHubRequestTimeoutSeconds)
            };
            httpClient.DefaultRequestHeaders.UserAgent.Add(
                new ProductInfoHeaderValue(settings.GitHubUserAgentProductName, settings.GitHubUserAgentProductVersion));
            httpClient.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", githubToken);
            httpClient.DefaultRequestHeaders.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));

            var results = new List<SecurityAdvisoryRecord>();

            foreach (var packageName in packageSet)
            {
                var cacheKey = packageName.Trim();
                var cacheEntry = PackageQueryCache.GetOrAdd(cacheKey, _ => new Lazy<Task<GitHubPackageQueryResult>>(
                    () => QueryNuGetAdvisoriesFromGitHubWithRetryAsync(
                    httpClient,
                    settings.GitHubGraphQlUrl,
                    settings.GitHubGraphQlNuGetQuery,
                        cacheKey,
                        cancellationToken),
                    LazyThreadSafetyMode.ExecutionAndPublication));

                var packageResult = await cacheEntry.Value;
                const string cacheStatus = "GitHubGraphQLApi/process-cache";

                diagnostics.Add(packageResult.StatusCode.HasValue
                    ? $"GitHub API package '{packageName}': HTTP {(int)packageResult.StatusCode.Value} ({packageResult.StatusCode.Value}), pages={packageResult.PageCount}, advisories={packageResult.Records.Count}, source={cacheStatus}."
                    : $"GitHub API package '{packageName}': request failed ({packageResult.ErrorMessage}), source={cacheStatus}.");

                if (!packageResult.Success)
                {
                    return new GitHubSecurityContextResult
                    {
                        AccessSucceeded = false,
                        Context = "[]",
                        ErrorMessage = packageResult.ErrorMessage,
                        Diagnostics = diagnostics
                    };
                }

                results.AddRange(packageResult.Records);
            }

            return new GitHubSecurityContextResult
            {
                AccessSucceeded = true,
                Context = JsonSerializer.Serialize(results, SerializerOptions),
                MatchedCount = results.Count,
                ErrorMessage = string.Empty,
                Diagnostics = diagnostics
            };
        }
        catch (OperationCanceledException ex) when (!cancellationToken.IsCancellationRequested)
        {
            return new GitHubSecurityContextResult
            {
                AccessSucceeded = false,
                Context = "[]",
                ErrorMessage = $"GitHub GraphQL request timed out after {GitHubRequestTimeoutSeconds} seconds. {ex.Message}",
                Diagnostics = diagnostics
            };
        }
        catch (HttpRequestException ex)
        {
            return new GitHubSecurityContextResult
            {
                AccessSucceeded = false,
                Context = "[]",
                ErrorMessage = $"GitHub GraphQL HTTP request failed. {ex.Message}",
                Diagnostics = diagnostics
            };
        }
        catch (JsonException ex)
        {
            return new GitHubSecurityContextResult
            {
                AccessSucceeded = false,
                Context = "[]",
                ErrorMessage = $"GitHub GraphQL response JSON could not be parsed. {ex.Message}",
                Diagnostics = diagnostics
            };
        }
        catch (Exception ex)
        {
            return new GitHubSecurityContextResult
            {
                AccessSucceeded = false,
                Context = "[]",
                ErrorMessage = $"Unexpected GitHub GraphQL retrieval failure. {ex.Message}",
                Diagnostics = diagnostics
            };
        }
    }

    private static async Task<GitHubPackageQueryResult> QueryNuGetAdvisoriesFromGitHubWithRetryAsync(
        HttpClient httpClient,
        string gitHubGraphQlUrl,
        string gitHubGraphQlNuGetQuery,
        string packageName,
        CancellationToken cancellationToken)
    {
        GitHubPackageQueryResult? lastResult = null;

        for (var attempt = 1; attempt <= GitHubMaxAttempts; attempt++)
        {
            lastResult = await QueryNuGetAdvisoriesFromGitHubAsync(
                httpClient,
                gitHubGraphQlUrl,
                gitHubGraphQlNuGetQuery,
                packageName,
                cancellationToken);

            if (!IsTransientGitHubResult(lastResult) || attempt == GitHubMaxAttempts)
            {
                return lastResult;
            }

            var delay = TimeSpan.FromMilliseconds(750 * attempt);
            Console.WriteLine($"[Retrieval] GitHub transient failure for '{packageName}' on attempt {attempt}/{GitHubMaxAttempts}. Retrying in {delay.TotalMilliseconds:0}ms.");
            await Task.Delay(delay, cancellationToken);
        }

        return lastResult ?? new GitHubPackageQueryResult
        {
            Success = false,
            StatusCode = null,
            Records = new List<SecurityAdvisoryRecord>(),
            ErrorMessage = "GitHub API request failed before a response was produced."
        };
    }

    private static async Task<GitHubPackageQueryResult> QueryNuGetAdvisoriesFromGitHubAsync(
        HttpClient httpClient,
        string gitHubGraphQlUrl,
        string gitHubGraphQlNuGetQuery,
        string packageName,
        CancellationToken cancellationToken)
    {
        try
        {
            var records = new List<SecurityAdvisoryRecord>();
            string? afterCursor = null;
            HttpStatusCode? lastStatusCode = null;

            for (var page = 1; page <= GitHubMaxPagesPerPackage; page++)
            {
                var payload = new
                {
                    query = gitHubGraphQlNuGetQuery,
                    variables = new
                    {
                        package = packageName,
                        after = afterCursor
                    }
                };

                using var content = new StringContent(JsonSerializer.Serialize(payload), Encoding.UTF8, "application/json");
                using var response = await httpClient.PostAsync(gitHubGraphQlUrl, content, cancellationToken);
                var statusCode = response.StatusCode;
                lastStatusCode = statusCode;
                var json = await response.Content.ReadAsStringAsync(cancellationToken);

                if (!response.IsSuccessStatusCode)
                {
                    return new GitHubPackageQueryResult
                    {
                        Success = false,
                        StatusCode = statusCode,
                        Records = new List<SecurityAdvisoryRecord>(),
                        PageCount = page,
                        ErrorMessage = $"GitHub GraphQL returned non-success HTTP status {(int)statusCode} ({statusCode})."
                    };
                }

                using var document = JsonDocument.Parse(json, InputJsonOptions);

                if (document.RootElement.TryGetProperty("errors", out var errors) &&
                    errors.ValueKind == JsonValueKind.Array &&
                    errors.GetArrayLength() > 0)
                {
                    return new GitHubPackageQueryResult
                    {
                        Success = false,
                        StatusCode = statusCode,
                        Records = new List<SecurityAdvisoryRecord>(),
                        PageCount = page,
                        ErrorMessage = $"GitHub GraphQL returned errors: {TruncateForDiagnostics(errors.GetRawText())}"
                    };
                }

                if (!document.RootElement.TryGetProperty("data", out var data) ||
                    !data.TryGetProperty("securityVulnerabilities", out var vulnerabilities) ||
                    !vulnerabilities.TryGetProperty("nodes", out var nodes) ||
                    nodes.ValueKind != JsonValueKind.Array)
                {
                    return new GitHubPackageQueryResult
                    {
                        Success = false,
                        StatusCode = statusCode,
                        Records = new List<SecurityAdvisoryRecord>(),
                        PageCount = page,
                        ErrorMessage = "GitHub GraphQL response schema does not contain data.securityVulnerabilities.nodes."
                    };
                }

                records.AddRange(ReadSecurityAdvisoryRecords(nodes, packageName));
                var pageInfo = ReadPageInfo(vulnerabilities);
                if (!pageInfo.IsPresent)
                {
                    return new GitHubPackageQueryResult
                    {
                        Success = false,
                        StatusCode = statusCode,
                        Records = records,
                        PageCount = page,
                        ErrorMessage = "GitHub GraphQL response schema does not contain data.securityVulnerabilities.pageInfo."
                    };
                }

                if (!pageInfo.HasNextPage)
                {
                    return new GitHubPackageQueryResult
                    {
                        Success = true,
                        StatusCode = statusCode,
                        Records = records,
                        PageCount = page,
                        ErrorMessage = string.Empty
                    };
                }

                if (string.IsNullOrWhiteSpace(pageInfo.EndCursor))
                {
                    return new GitHubPackageQueryResult
                    {
                        Success = false,
                        StatusCode = statusCode,
                        Records = records,
                        PageCount = page,
                        ErrorMessage = "GitHub GraphQL response indicates another advisory page but does not provide pageInfo.endCursor."
                    };
                }

                afterCursor = pageInfo.EndCursor;
            }

            return new GitHubPackageQueryResult
            {
                Success = false,
                StatusCode = lastStatusCode,
                Records = records,
                PageCount = GitHubMaxPagesPerPackage,
                ErrorMessage = $"GitHub GraphQL advisory pagination exceeded the safety limit of {GitHubMaxPagesPerPackage} page(s) for package '{packageName}'."
            };
        }
        catch (TaskCanceledException ex) when (!cancellationToken.IsCancellationRequested)
        {
            return new GitHubPackageQueryResult
            {
                Success = false,
                StatusCode = null,
                Records = new List<SecurityAdvisoryRecord>(),
                PageCount = 0,
                ErrorMessage = $"GitHub request timed out after {GitHubRequestTimeoutSeconds} seconds. {ex.Message}"
            };
        }
        catch (Exception ex) when (ex is HttpRequestException or JsonException)
        {
            return new GitHubPackageQueryResult
            {
                Success = false,
                StatusCode = null,
                Records = new List<SecurityAdvisoryRecord>(),
                PageCount = 0,
                ErrorMessage = ex.Message
            };
        }
    }

    private static List<SecurityAdvisoryRecord> ReadSecurityAdvisoryRecords(JsonElement nodes, string packageName)
    {
        var records = new List<SecurityAdvisoryRecord>();

        foreach (var node in nodes.EnumerateArray())
        {
            if (node.ValueKind != JsonValueKind.Object)
            {
                continue;
            }

            var advisory = node.TryGetProperty("advisory", out var advisoryElement) ? advisoryElement : default;
            var identifiers = advisory.ValueKind == JsonValueKind.Object && advisory.TryGetProperty("identifiers", out var identifierArray)
                ? identifierArray
                : default;

            records.Add(new SecurityAdvisoryRecord
            {
                PackageName = packageName,
                VulnerableVersionRange = ReadString(node, "vulnerableVersionRange"),
                Severity = ReadString(node, "severity"),
                GHSA = advisory.ValueKind == JsonValueKind.Object ? ReadString(advisory, "ghsaId") : string.Empty,
                CVE = ExtractIdentifierValue(identifiers, "CVE"),
                Summary = advisory.ValueKind == JsonValueKind.Object ? ReadString(advisory, "summary") : string.Empty,
                ReferenceUrl = advisory.ValueKind == JsonValueKind.Object ? ReadString(advisory, "permalink") : string.Empty,
                FirstPatchedVersion = ReadFirstPatchedVersion(node)
            });
        }

        return records;
    }

    private static GitHubPageInfo ReadPageInfo(JsonElement vulnerabilities)
    {
        if (!vulnerabilities.TryGetProperty("pageInfo", out var pageInfo) ||
            pageInfo.ValueKind != JsonValueKind.Object)
        {
            return new GitHubPageInfo { IsPresent = false };
        }

        return new GitHubPageInfo
        {
            IsPresent = true,
            HasNextPage = pageInfo.TryGetProperty("hasNextPage", out var hasNextPage) &&
                          hasNextPage.ValueKind == JsonValueKind.True,
            EndCursor = ReadString(pageInfo, "endCursor")
        };
    }

    private static bool IsTransientGitHubResult(GitHubPackageQueryResult result)
    {
        if (result.Success)
        {
            return false;
        }

        if (!result.StatusCode.HasValue)
        {
            return true;
        }

        return result.StatusCode.Value == HttpStatusCode.TooManyRequests ||
               (int)result.StatusCode.Value >= 500;
    }

    private static string ResolveGitHubToken(SecurityReferenceSettings settings)
    {
        var environmentToken = Environment.GetEnvironmentVariable(GitHubTokenEnvironmentVariableName);

        if (!string.IsNullOrWhiteSpace(environmentToken))
        {
            return environmentToken;
        }

        return settings.GitHubToken;
    }

    private static SecurityReferenceSettings GetSecurityReferenceSettings()
    {
        var settings = new SecurityReferenceSettings();

        foreach (var path in GetAppSettingsPaths())
        {
            if (!File.Exists(path))
            {
                continue;
            }

            using var stream = File.OpenRead(path);
            using var document = JsonDocument.Parse(stream, InputJsonOptions);

            if (!document.RootElement.TryGetProperty("SecurityReference", out var section) ||
                section.ValueKind != JsonValueKind.Object)
            {
                continue;
            }

            settings.GitHubGraphQlUrl = ReadString(section, "GitHubGraphQlUrl", settings.GitHubGraphQlUrl);
            settings.GitHubGraphQlNuGetQuery = ReadString(section, "GitHubGraphQlNuGetQuery", settings.GitHubGraphQlNuGetQuery);
            settings.GitHubToken = ReadString(section, "GitHubToken", settings.GitHubToken);
            settings.GitHubUserAgentProductName = ReadString(section, "GitHubUserAgentProductName", settings.GitHubUserAgentProductName);
            settings.GitHubUserAgentProductVersion = ReadString(section, "GitHubUserAgentProductVersion", settings.GitHubUserAgentProductVersion);
        }

        ValidateSecurityReferenceSettings(settings);
        return settings;
    }

    private static void ValidateSecurityReferenceSettings(SecurityReferenceSettings settings)
    {
        if (string.IsNullOrWhiteSpace(settings.GitHubGraphQlUrl))
        {
            throw new InvalidOperationException("Konfigurasi 'SecurityReference:GitHubGraphQlUrl' wajib diisi.");
        }

        if (string.IsNullOrWhiteSpace(settings.GitHubGraphQlNuGetQuery))
        {
            throw new InvalidOperationException("Konfigurasi 'SecurityReference:GitHubGraphQlNuGetQuery' wajib diisi.");
        }

        if (string.IsNullOrWhiteSpace(settings.GitHubUserAgentProductName) ||
            string.IsNullOrWhiteSpace(settings.GitHubUserAgentProductVersion))
        {
            throw new InvalidOperationException("Konfigurasi 'SecurityReference:GitHubUserAgentProductName' dan 'SecurityReference:GitHubUserAgentProductVersion' wajib diisi.");
        }
    }

    private static IEnumerable<string> GetAppSettingsPaths()
    {
        var basePath = Path.Combine(AppContext.BaseDirectory, "appsettings.json");
        yield return basePath;

        var currentPath = Path.Combine(Directory.GetCurrentDirectory(), "appsettings.json");

        if (!string.Equals(basePath, currentPath, StringComparison.OrdinalIgnoreCase))
        {
            yield return currentPath;
        }
    }

    private static string ReadFirstPatchedVersion(JsonElement node)
    {
        if (!node.TryGetProperty("firstPatchedVersion", out var patchedVersion) ||
            patchedVersion.ValueKind != JsonValueKind.Object)
        {
            return string.Empty;
        }

        return ReadString(patchedVersion, "identifier", "Identifier");
    }

    private static string ExtractIdentifierValue(JsonElement identifiers, string identifierType)
    {
        if (identifiers.ValueKind != JsonValueKind.Array)
        {
            return string.Empty;
        }

        foreach (var identifier in identifiers.EnumerateArray())
        {
            if (identifier.ValueKind != JsonValueKind.Object)
            {
                continue;
            }

            if (identifier.TryGetProperty("type", out var type) &&
                identifier.TryGetProperty("value", out var value) &&
                string.Equals(type.GetString(), identifierType, StringComparison.OrdinalIgnoreCase))
            {
                return value.GetString() ?? string.Empty;
            }
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

    private static string ReadString(JsonElement section, string propertyName, string currentValue)
    {
        if (!section.TryGetProperty(propertyName, out var property) || property.ValueKind != JsonValueKind.String)
        {
            return currentValue;
        }

        var value = property.GetString();
        return string.IsNullOrWhiteSpace(value) ? currentValue : value;
    }

    private static string TruncateForDiagnostics(string value, int maxLength = 500)
    {
        if (string.IsNullOrWhiteSpace(value) || value.Length <= maxLength)
        {
            return value;
        }

        return value[..maxLength] + "...";
    }

    public sealed class SecurityContextResult
    {
        public string Context { get; set; } = "[]";
        public string Source { get; set; } = "None";
        public List<string> Diagnostics { get; set; } = new();
    }

    private sealed class GitHubSecurityContextResult
    {
        public bool AccessSucceeded { get; set; }
        public string Context { get; set; } = "[]";
        public int MatchedCount { get; set; }
        public string ErrorMessage { get; set; } = string.Empty;
        public List<string> Diagnostics { get; set; } = new();
    }

    private sealed class GitHubPackageQueryResult
    {
        public bool Success { get; set; }
        public HttpStatusCode? StatusCode { get; set; }
        public List<SecurityAdvisoryRecord> Records { get; set; } = new();
        public int PageCount { get; set; }
        public string ErrorMessage { get; set; } = string.Empty;
    }

    private sealed class GitHubPageInfo
    {
        public bool IsPresent { get; set; }
        public bool HasNextPage { get; set; }
        public string EndCursor { get; set; } = string.Empty;
    }

    private sealed class SecurityReferenceSettings
    {
        public string GitHubGraphQlUrl { get; set; } = "https://api.github.com/graphql";
        public string GitHubGraphQlNuGetQuery { get; set; } = "query($package:String!,$after:String){ securityVulnerabilities(first:100, after:$after, ecosystem:NUGET, package:$package){ pageInfo{ hasNextPage endCursor } nodes{ package{ name } vulnerableVersionRange firstPatchedVersion{ identifier } severity advisory{ ghsaId summary permalink identifiers{ type value } } } } }";
        public string GitHubToken { get; set; } = string.Empty;
        public string GitHubUserAgentProductName { get; set; } = "GeminiNuGetAuditor";
        public string GitHubUserAgentProductVersion { get; set; } = "1.0";
    }

    private sealed class SecurityAdvisoryRecord
    {
        public string PackageName { get; set; } = string.Empty;
        public string VulnerableVersionRange { get; set; } = string.Empty;
        public string Severity { get; set; } = string.Empty;
        public string GHSA { get; set; } = string.Empty;
        public string CVE { get; set; } = string.Empty;
        public string Summary { get; set; } = string.Empty;
        public string ReferenceUrl { get; set; } = string.Empty;
        public string FirstPatchedVersion { get; set; } = string.Empty;
    }
}
