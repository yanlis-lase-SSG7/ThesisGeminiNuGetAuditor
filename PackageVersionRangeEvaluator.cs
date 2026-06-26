using System.Text.RegularExpressions;

namespace GeminiNuGetAuditor;

public static class PackageVersionRangeEvaluator
{
    public static VersionRangeEvaluation Evaluate(string currentVersion, string vulnerableVersionRange)
    {
        if (!TryParseVersion(currentVersion, out var version))
        {
            return VersionRangeEvaluation.Unknown($"Current version '{currentVersion}' could not be parsed.");
        }

        if (string.IsNullOrWhiteSpace(vulnerableVersionRange))
        {
            return VersionRangeEvaluation.Unknown("Vulnerable version range is empty.");
        }

        var range = vulnerableVersionRange.Trim();
        var alternatives = Regex.Split(range, @"\s*\|\|\s*")
            .Where(x => !string.IsNullOrWhiteSpace(x))
            .ToList();

        foreach (var alternative in alternatives.Count == 0 ? new List<string> { range } : alternatives)
        {
            var result = EvaluateAlternative(version, alternative.Trim());
            if (result.IsKnown && result.IsAffected)
            {
                return result;
            }
        }

        return alternatives
            .Select(x => EvaluateAlternative(version, x.Trim()))
            .FirstOrDefault(x => x.IsKnown) ?? VersionRangeEvaluation.Unknown($"Unsupported range format: {range}");
    }

    private static VersionRangeEvaluation EvaluateAlternative(PackageVersion version, string range)
    {
        if (TryEvaluateNuGetInterval(version, range, out var intervalResult))
        {
            return intervalResult;
        }

        var comparators = range
            .Split(',', StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries)
            .SelectMany(part => Regex.Matches(part, @"(<=|>=|<|>|=)?\s*([0-9A-Za-z][0-9A-Za-z.\-+]*)")
                .Select(match => (Operator: string.IsNullOrWhiteSpace(match.Groups[1].Value) ? "=" : match.Groups[1].Value, Version: match.Groups[2].Value)))
            .ToList();

        if (comparators.Count == 0)
        {
            return VersionRangeEvaluation.Unknown($"Unsupported range format: {range}");
        }

        foreach (var comparator in comparators)
        {
            if (!TryParseVersion(comparator.Version, out var boundary))
            {
                return VersionRangeEvaluation.Unknown($"Boundary version '{comparator.Version}' could not be parsed.");
            }

            var comparison = version.CompareTo(boundary);
            var satisfied = comparator.Operator switch
            {
                "<" => comparison < 0,
                "<=" => comparison <= 0,
                ">" => comparison > 0,
                ">=" => comparison >= 0,
                "=" => comparison == 0,
                _ => false
            };

            if (!satisfied)
            {
                return VersionRangeEvaluation.NotAffected($"Version {version.Original} does not satisfy '{comparator.Operator} {boundary.Original}'.");
            }
        }

        return VersionRangeEvaluation.Affected($"Version {version.Original} satisfies range '{range}'.");
    }

    private static bool TryEvaluateNuGetInterval(PackageVersion version, string range, out VersionRangeEvaluation result)
    {
        result = VersionRangeEvaluation.Unknown(string.Empty);
        var trimmed = range.Trim();

        if (trimmed.Length < 2 ||
            (trimmed[0] != '[' && trimmed[0] != '(') ||
            (trimmed[^1] != ']' && trimmed[^1] != ')'))
        {
            return false;
        }

        var inclusiveLower = trimmed[0] == '[';
        var inclusiveUpper = trimmed[^1] == ']';
        var inner = trimmed[1..^1].Trim();

        if (!inner.Contains(',', StringComparison.Ordinal))
        {
            if (!TryParseVersion(inner, out var exact))
            {
                result = VersionRangeEvaluation.Unknown($"Exact interval version '{inner}' could not be parsed.");
                return true;
            }

            result = version.CompareTo(exact) == 0
                ? VersionRangeEvaluation.Affected($"Version {version.Original} equals exact range '{range}'.")
                : VersionRangeEvaluation.NotAffected($"Version {version.Original} does not equal exact range '{range}'.");
            return true;
        }

        var parts = inner.Split(',', 2, StringSplitOptions.TrimEntries);
        var lowerOk = true;
        var upperOk = true;

        if (!string.IsNullOrWhiteSpace(parts[0]))
        {
            if (!TryParseVersion(parts[0], out var lower))
            {
                result = VersionRangeEvaluation.Unknown($"Lower interval version '{parts[0]}' could not be parsed.");
                return true;
            }

            var comparison = version.CompareTo(lower);
            lowerOk = inclusiveLower ? comparison >= 0 : comparison > 0;
        }

        if (!string.IsNullOrWhiteSpace(parts[1]))
        {
            if (!TryParseVersion(parts[1], out var upper))
            {
                result = VersionRangeEvaluation.Unknown($"Upper interval version '{parts[1]}' could not be parsed.");
                return true;
            }

            var comparison = version.CompareTo(upper);
            upperOk = inclusiveUpper ? comparison <= 0 : comparison < 0;
        }

        result = lowerOk && upperOk
            ? VersionRangeEvaluation.Affected($"Version {version.Original} is inside interval '{range}'.")
            : VersionRangeEvaluation.NotAffected($"Version {version.Original} is outside interval '{range}'.");
        return true;
    }

    private static bool TryParseVersion(string value, out PackageVersion version)
    {
        version = default;
        if (string.IsNullOrWhiteSpace(value))
        {
            return false;
        }

        var cleaned = value.Trim().Trim('[', ']', '(', ')');
        if (string.Equals(cleaned, "0", StringComparison.OrdinalIgnoreCase))
        {
            cleaned = "0.0.0";
        }

        var plusIndex = cleaned.IndexOf('+', StringComparison.Ordinal);
        if (plusIndex >= 0)
        {
            cleaned = cleaned[..plusIndex];
        }

        var prerelease = string.Empty;
        var prereleaseIndex = cleaned.IndexOf('-', StringComparison.Ordinal);
        if (prereleaseIndex >= 0)
        {
            prerelease = cleaned[(prereleaseIndex + 1)..];
            cleaned = cleaned[..prereleaseIndex];
        }

        var segments = cleaned.Split('.', StringSplitOptions.RemoveEmptyEntries);
        if (segments.Length == 0 || segments.Length > 4)
        {
            return false;
        }

        var numbers = new int[4];
        for (var i = 0; i < segments.Length; i++)
        {
            if (!int.TryParse(segments[i], out numbers[i]))
            {
                return false;
            }
        }

        version = new PackageVersion(value.Trim(), numbers, prerelease);
        return true;
    }

    private readonly record struct PackageVersion(string Original, int[] Numbers, string Prerelease) : IComparable<PackageVersion>
    {
        public int CompareTo(PackageVersion other)
        {
            for (var i = 0; i < 4; i++)
            {
                var comparison = Numbers[i].CompareTo(other.Numbers[i]);
                if (comparison != 0)
                {
                    return comparison;
                }
            }

            if (string.IsNullOrWhiteSpace(Prerelease) && string.IsNullOrWhiteSpace(other.Prerelease))
            {
                return 0;
            }

            if (string.IsNullOrWhiteSpace(Prerelease))
            {
                return 1;
            }

            if (string.IsNullOrWhiteSpace(other.Prerelease))
            {
                return -1;
            }

            return string.Compare(Prerelease, other.Prerelease, StringComparison.OrdinalIgnoreCase);
        }
    }
}

public sealed class VersionRangeEvaluation
{
    public bool IsKnown { get; init; }
    public bool IsAffected { get; init; }
    public string Reason { get; init; } = string.Empty;

    public static VersionRangeEvaluation Affected(string reason) => new() { IsKnown = true, IsAffected = true, Reason = reason };
    public static VersionRangeEvaluation NotAffected(string reason) => new() { IsKnown = true, IsAffected = false, Reason = reason };
    public static VersionRangeEvaluation Unknown(string reason) => new() { IsKnown = false, IsAffected = false, Reason = reason };
}
