using System.Net;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;

namespace GeminiNuGetAuditor;

public static class SecurityReferenceProvider
{
    private const string GitHubTokenEnvironmentVariableName = "GITHUB_TOKEN";
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

    public static async Task<SecurityContextResult> GetSecurityContextWithDiagnosticsAsync(List<string> packages, CancellationToken cancellationToken = default)
    {
        if (packages is null || packages.Count == 0)
        {
            return new SecurityContextResult
            {
                Context = "[]",
                Source = "None",
                Diagnostics = new List<string> { "No package input. Retrieval skipped." }
            };
        }

        var packageSet = new HashSet<string>(
            packages.Where(x => !string.IsNullOrWhiteSpace(x)).Select(x => x.Trim()),
            StringComparer.OrdinalIgnoreCase);

        if (packageSet.Count == 0)
        {
            return new SecurityContextResult
            {
                Context = "[]",
                Source = "None",
                Diagnostics = new List<string> { "Package input contains only empty names. Retrieval skipped." }
            };
        }

        var settings = GetSecurityReferenceSettings();
        var diagnostics = new List<string>();

        var localFileResult = TryGetSecurityContextFromLocalFile(packageSet, settings.AdvisoryDbFileName);

        if (localFileResult.IsLoaded)
        {
            diagnostics.Add($"Local advisory file found: {localFileResult.FilePath}.");
            diagnostics.Add($"Matched advisory entries from local file: {localFileResult.MatchedCount}.");

            return new SecurityContextResult
            {
                Context = localFileResult.Context,
                Source = "LocalFile",
                Diagnostics = diagnostics
            };
        }

        diagnostics.Add($"Local advisory file not found: {settings.AdvisoryDbFileName}.");

        var apiResult = await TryGetSecurityContextFromGitHubApiAsync(packageSet, settings, cancellationToken);
        diagnostics.AddRange(apiResult.Diagnostics);

        if (apiResult.AccessSucceeded)
        {
            return new SecurityContextResult
            {
                Context = apiResult.Context,
                Source = "GitHubApi",
                Diagnostics = diagnostics
            };
        }

        var fallbackContext = GetFallbackSecurityContext(packageSet, settings, out var fallbackMatchCount);
        diagnostics.Add($"Fallback advisory entries matched: {fallbackMatchCount}.");

        return new SecurityContextResult
        {
            Context = fallbackContext,
            Source = "Fallback",
            Diagnostics = diagnostics
        };
    }

    private static LocalSecurityContextResult TryGetSecurityContextFromLocalFile(HashSet<string> packageSet, string advisoryDbFileName)
    {
        var advisoryDbPath = Path.Combine(AppContext.BaseDirectory, advisoryDbFileName);

        if (!File.Exists(advisoryDbPath))
        {
            advisoryDbPath = Path.Combine(Directory.GetCurrentDirectory(), advisoryDbFileName);
        }

        if (!File.Exists(advisoryDbPath))
        {
            return new LocalSecurityContextResult
            {
                IsLoaded = false,
                Context = "[]",
                FilePath = advisoryDbPath,
                MatchedCount = 0
            };
        }

        using var stream = File.OpenRead(advisoryDbPath);
        using var document = JsonDocument.Parse(stream, InputJsonOptions);

        var matched = new List<JsonElement>();

        foreach (var advisory in GetAdvisoryArray(document.RootElement))
        {
            var packageName = TryGetPackageName(advisory);

            if (!string.IsNullOrWhiteSpace(packageName) && packageSet.Contains(packageName))
            {
                matched.Add(advisory.Clone());
            }
        }

        return new LocalSecurityContextResult
        {
            IsLoaded = true,
            Context = JsonSerializer.Serialize(matched, SerializerOptions),
            FilePath = advisoryDbPath,
            MatchedCount = matched.Count
        };
    }

    private static async Task<GitHubSecurityContextResult> TryGetSecurityContextFromGitHubApiAsync(
        HashSet<string> packageSet,
        SecurityReferenceSettings settings,
        CancellationToken cancellationToken)
    {
        var githubToken = ResolveGitHubToken(settings);

        if (string.IsNullOrWhiteSpace(githubToken))
        {
            return new GitHubSecurityContextResult
            {
                AccessSucceeded = false,
                Context = "[]",
                Diagnostics = new List<string>
                {
                    $"GitHub token is empty. Set env var '{GitHubTokenEnvironmentVariableName}' or fill 'SecurityReference:GitHubToken'."
                }
            };
        }

        if (string.IsNullOrWhiteSpace(settings.GitHubGraphQlUrl))
        {
            return new GitHubSecurityContextResult
            {
                AccessSucceeded = false,
                Context = "[]",
                Diagnostics = new List<string> { "GitHub GraphQL URL is empty." }
            };
        }

        using var httpClient = new HttpClient();
        httpClient.DefaultRequestHeaders.UserAgent.Add(new ProductInfoHeaderValue(settings.GitHubUserAgentProductName, settings.GitHubUserAgentProductVersion));
        httpClient.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", githubToken);
        httpClient.DefaultRequestHeaders.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));

        var results = new List<SecurityAdvisoryRecord>();
        var diagnostics = new List<string>();
        var accessSucceeded = false;

        foreach (var packageName in packageSet)
        {
            var apiResponse = await QueryNuGetAdvisoriesFromGitHubAsync(httpClient, settings.GitHubGraphQlUrl, settings.GitHubGraphQlNuGetQuery, packageName, cancellationToken);

            if (apiResponse.StatusCode.HasValue)
            {
                diagnostics.Add($"GitHub API package '{packageName}': HTTP {(int)apiResponse.StatusCode.Value} ({apiResponse.StatusCode.Value}), advisories={apiResponse.Records.Count}.");

                if (apiResponse.StatusCode.Value == HttpStatusCode.OK)
                {
                    accessSucceeded = true;
                }

                if (apiResponse.StatusCode.Value is HttpStatusCode.Unauthorized or HttpStatusCode.Forbidden)
                {
                    diagnostics.Add("GitHub token unauthorized/forbidden. Remaining packages skipped to prevent repeated failed calls.");
                    break;
                }
            }
            else
            {
                diagnostics.Add($"GitHub API package '{packageName}': request failed ({apiResponse.ErrorMessage}).");
            }

            results.AddRange(apiResponse.Records);
        }

        return new GitHubSecurityContextResult
        {
            AccessSucceeded = accessSucceeded,
            Context = JsonSerializer.Serialize(results, SerializerOptions),
            Diagnostics = diagnostics
        };
    }

    private static async Task<GitHubPackageQueryResult> QueryNuGetAdvisoriesFromGitHubAsync(
        HttpClient httpClient,
        string gitHubGraphQlUrl,
        string gitHubGraphQlNuGetQuery,
        string packageName,
        CancellationToken cancellationToken)
    {
        var payload = new
        {
            query = gitHubGraphQlNuGetQuery,
            variables = new
            {
                package = packageName
            }
        };

        using var content = new StringContent(JsonSerializer.Serialize(payload), Encoding.UTF8, "application/json");

        try
        {
            using var response = await httpClient.PostAsync(gitHubGraphQlUrl, content, cancellationToken);
            var statusCode = response.StatusCode;

            if (!response.IsSuccessStatusCode)
            {
                return new GitHubPackageQueryResult
                {
                    StatusCode = statusCode,
                    Records = new List<SecurityAdvisoryRecord>(),
                    ErrorMessage = $"Non-success status code: {(int)statusCode}"
                };
            }

            var json = await response.Content.ReadAsStringAsync(cancellationToken);
            using var document = JsonDocument.Parse(json);

            if (!document.RootElement.TryGetProperty("data", out var data) ||
                !data.TryGetProperty("securityVulnerabilities", out var vulnerabilities) ||
                !vulnerabilities.TryGetProperty("nodes", out var nodes) ||
                nodes.ValueKind != JsonValueKind.Array)
            {
                return new GitHubPackageQueryResult
                {
                    StatusCode = statusCode,
                    Records = new List<SecurityAdvisoryRecord>(),
                    ErrorMessage = "Response schema does not contain expected nodes."
                };
            }

            var records = new List<SecurityAdvisoryRecord>();

            foreach (var node in nodes.EnumerateArray())
            {
                var advisory = node.TryGetProperty("advisory", out var advisoryElement) ? advisoryElement : default;
                var identifiers = advisory.ValueKind == JsonValueKind.Object && advisory.TryGetProperty("identifiers", out var identifierArray)
                    ? identifierArray
                    : default;

                records.Add(new SecurityAdvisoryRecord
                {
                    PackageName = packageName,
                    VulnerableVersionRange = node.TryGetProperty("vulnerableVersionRange", out var versionRange) ? versionRange.GetString() ?? string.Empty : string.Empty,
                    Severity = node.TryGetProperty("severity", out var severity) ? severity.GetString() ?? string.Empty : string.Empty,
                    GHSA = advisory.ValueKind == JsonValueKind.Object && advisory.TryGetProperty("ghsaId", out var ghsa) ? ghsa.GetString() ?? string.Empty : string.Empty,
                    CVE = ExtractIdentifierValue(identifiers, "CVE"),
                    Summary = advisory.ValueKind == JsonValueKind.Object && advisory.TryGetProperty("summary", out var summary) ? summary.GetString() ?? string.Empty : string.Empty,
                    ReferenceUrl = advisory.ValueKind == JsonValueKind.Object && advisory.TryGetProperty("permalink", out var permalink) ? permalink.GetString() ?? string.Empty : string.Empty,
                    FirstPatchedVersion = node.TryGetProperty("firstPatchedVersion", out var patchedVersion) &&
                                          patchedVersion.ValueKind == JsonValueKind.Object &&
                                          patchedVersion.TryGetProperty("identifier", out var identifier)
                        ? identifier.GetString() ?? string.Empty
                        : string.Empty
                });
            }

            return new GitHubPackageQueryResult
            {
                StatusCode = statusCode,
                Records = records,
                ErrorMessage = string.Empty
            };
        }
        catch (Exception ex)
        {
            return new GitHubPackageQueryResult
            {
                StatusCode = null,
                Records = new List<SecurityAdvisoryRecord>(),
                ErrorMessage = ex.Message
            };
        }
    }

    private static string ResolveGitHubToken(SecurityReferenceSettings settings)
    {
        if (!string.IsNullOrWhiteSpace(settings.GitHubToken))
        {
            return settings.GitHubToken;
        }

        return Environment.GetEnvironmentVariable(GitHubTokenEnvironmentVariableName) ?? string.Empty;
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

            if (!document.RootElement.TryGetProperty("SecurityReference", out var section) || section.ValueKind != JsonValueKind.Object)
            {
                continue;
            }

            settings.AdvisoryDbFileName = ReadString(section, "AdvisoryDbFileName", settings.AdvisoryDbFileName);
            settings.GitHubGraphQlUrl = ReadString(section, "GitHubGraphQlUrl", settings.GitHubGraphQlUrl);
            settings.GitHubGraphQlNuGetQuery = ReadString(section, "GitHubGraphQlNuGetQuery", settings.GitHubGraphQlNuGetQuery);
            settings.GitHubToken = ReadString(section, "GitHubToken", settings.GitHubToken);
            settings.GitHubUserAgentProductName = ReadString(section, "GitHubUserAgentProductName", settings.GitHubUserAgentProductName);
            settings.GitHubUserAgentProductVersion = ReadString(section, "GitHubUserAgentProductVersion", settings.GitHubUserAgentProductVersion);
            settings.FallbackAdvisoriesJson = ReadArrayRawJson(section, "FallbackAdvisories", settings.FallbackAdvisoriesJson);
        }

        ValidateSecurityReferenceSettings(settings);
        return settings;
    }

    private static void ValidateSecurityReferenceSettings(SecurityReferenceSettings settings)
    {
        if (string.IsNullOrWhiteSpace(settings.AdvisoryDbFileName))
        {
            throw new InvalidOperationException("Konfigurasi 'SecurityReference:AdvisoryDbFileName' wajib diisi.");
        }

        if (string.IsNullOrWhiteSpace(settings.GitHubGraphQlUrl))
        {
            throw new InvalidOperationException("Konfigurasi 'SecurityReference:GitHubGraphQlUrl' wajib diisi.");
        }

        if (string.IsNullOrWhiteSpace(settings.GitHubGraphQlNuGetQuery))
        {
            throw new InvalidOperationException("Konfigurasi 'SecurityReference:GitHubGraphQlNuGetQuery' wajib diisi.");
        }

        if (string.IsNullOrWhiteSpace(settings.GitHubUserAgentProductName) || string.IsNullOrWhiteSpace(settings.GitHubUserAgentProductVersion))
        {
            throw new InvalidOperationException("Konfigurasi 'SecurityReference:GitHubUserAgentProductName' dan 'SecurityReference:GitHubUserAgentProductVersion' wajib diisi.");
        }

        if (string.IsNullOrWhiteSpace(settings.FallbackAdvisoriesJson))
        {
            throw new InvalidOperationException("Konfigurasi 'SecurityReference:FallbackAdvisories' wajib diisi.");
        }
    }

    private static IEnumerable<string> GetAppSettingsPaths()
    {
        var baseLocalPath = Path.Combine(AppContext.BaseDirectory, "appsettings.local.json");
        yield return baseLocalPath;

        var basePath = Path.Combine(AppContext.BaseDirectory, "appsettings.json");
        yield return basePath;

        var currentLocalPath = Path.Combine(Directory.GetCurrentDirectory(), "appsettings.local.json");

        if (!string.Equals(baseLocalPath, currentLocalPath, StringComparison.OrdinalIgnoreCase))
        {
            yield return currentLocalPath;
        }

        var currentPath = Path.Combine(Directory.GetCurrentDirectory(), "appsettings.json");

        if (!string.Equals(basePath, currentPath, StringComparison.OrdinalIgnoreCase))
        {
            yield return currentPath;
        }
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

    private static string ReadString(JsonElement section, string propertyName, string currentValue)
    {
        if (!section.TryGetProperty(propertyName, out var property) || property.ValueKind != JsonValueKind.String)
        {
            return currentValue;
        }

        var value = property.GetString();
        return string.IsNullOrWhiteSpace(value) ? currentValue : value;
    }

    private static string ReadArrayRawJson(JsonElement section, string propertyName, string currentValue)
    {
        if (!section.TryGetProperty(propertyName, out var property) || property.ValueKind != JsonValueKind.Array)
        {
            return currentValue;
        }

        return property.GetRawText();
    }

    private static string GetFallbackSecurityContext(HashSet<string> packageSet, SecurityReferenceSettings settings, out int matchedCount)
    {
        using var document = JsonDocument.Parse(settings.FallbackAdvisoriesJson, InputJsonOptions);
        var matched = new List<JsonElement>();

        foreach (var advisory in document.RootElement.EnumerateArray())
        {
            var packageName = TryGetPackageName(advisory);

            if (!string.IsNullOrWhiteSpace(packageName) && packageSet.Contains(packageName))
            {
                matched.Add(advisory.Clone());
            }
        }

        matchedCount = matched.Count;
        return JsonSerializer.Serialize(matched, SerializerOptions);
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

    public sealed class SecurityContextResult
    {
        public string Context { get; set; } = "[]";
        public string Source { get; set; } = "None";
        public List<string> Diagnostics { get; set; } = new();
    }

    private sealed class LocalSecurityContextResult
    {
        public bool IsLoaded { get; set; }
        public string Context { get; set; } = "[]";
        public string FilePath { get; set; } = string.Empty;
        public int MatchedCount { get; set; }
    }

    private sealed class GitHubSecurityContextResult
    {
        public bool AccessSucceeded { get; set; }
        public string Context { get; set; } = "[]";
        public List<string> Diagnostics { get; set; } = new();
    }

    private sealed class GitHubPackageQueryResult
    {
        public HttpStatusCode? StatusCode { get; set; }
        public List<SecurityAdvisoryRecord> Records { get; set; } = new();
        public string ErrorMessage { get; set; } = string.Empty;
    }

    private sealed class SecurityReferenceSettings
    {
        public string AdvisoryDbFileName { get; set; } = string.Empty;
        public string GitHubGraphQlUrl { get; set; } = string.Empty;
        public string GitHubGraphQlNuGetQuery { get; set; } = string.Empty;
        public string GitHubToken { get; set; } = string.Empty;
        public string GitHubUserAgentProductName { get; set; } = string.Empty;
        public string GitHubUserAgentProductVersion { get; set; } = string.Empty;
        public string FallbackAdvisoriesJson { get; set; } = string.Empty;
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
