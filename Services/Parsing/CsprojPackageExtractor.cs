using System.Text;
using System.Text.RegularExpressions;
using System.Xml.Linq;

namespace GeminiNuGetAuditor;

public static class CsprojPackageExtractor
{
    public static IReadOnlyList<NuGetPackageReference> ExtractPackageReferences(string filePath)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(filePath);

        if (!File.Exists(filePath))
        {
            throw new FileNotFoundException("The .csproj file was not found.", filePath);
        }

        XDocument document;
        try
        {
            document = XDocument.Load(filePath, LoadOptions.PreserveWhitespace | LoadOptions.SetLineInfo);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or System.Xml.XmlException)
        {
            throw new InvalidOperationException($"Unable to parse .csproj file '{filePath}'.", ex);
        }

        var projectDirectory = Path.GetDirectoryName(Path.GetFullPath(filePath)) ?? Directory.GetCurrentDirectory();
        var properties = LoadMsBuildProperties(projectDirectory, document);
        var centralPackageVersions = LoadCentralPackageVersions(projectDirectory, properties);

        return document
            .Descendants()
            .Where(x => x.Name.LocalName == "PackageReference" && x.Attribute("Remove") is null)
            .Select(x => new NuGetPackageReference
            {
                PackageName = ReadPackageName(x),
                CurrentVersion = ReadPackageVersion(x, centralPackageVersions, properties)
            })
            .Where(x => !string.IsNullOrWhiteSpace(x.PackageName))
            .GroupBy(x => x.PackageName, StringComparer.OrdinalIgnoreCase)
            .Select(x => x.First())
            .ToList();
    }

    public static string ExtractPackagesFromCsproj(string filePath)
    {
        var packages = ExtractPackageReferences(filePath);

        if (packages.Count == 0)
        {
            return "No PackageReference entries were found in the project file.";
        }

        var builder = new StringBuilder();
        builder.AppendLine("NuGet packages found in the project:");

        foreach (var package in packages)
        {
            builder.AppendLine($"- {package.PackageName}: {package.CurrentVersion}");
        }

        return builder.ToString().TrimEnd();
    }

    private static string ReadPackageName(XElement element)
    {
        return element.Attribute("Include")?.Value?.Trim()
            ?? element.Attribute("Update")?.Value?.Trim()
            ?? string.Empty;
    }

    private static string ReadPackageVersion(
        XElement element,
        IReadOnlyDictionary<string, string> centralPackageVersions,
        IReadOnlyDictionary<string, string> properties)
    {
        var packageName = ReadPackageName(element);
        var attributeVersion = element.Attribute("Version")?.Value?.Trim()
            ?? element.Attribute("VersionOverride")?.Value?.Trim();
        if (!string.IsNullOrWhiteSpace(attributeVersion))
        {
            return ResolveProperties(attributeVersion, properties);
        }

        var childVersion = element.Elements()
            .FirstOrDefault(e => e.Name.LocalName is "Version" or "VersionOverride")
            ?.Value
            ?.Trim();

        if (!string.IsNullOrWhiteSpace(childVersion))
        {
            return ResolveProperties(childVersion, properties);
        }

        if (!string.IsNullOrWhiteSpace(packageName) &&
            centralPackageVersions.TryGetValue(packageName, out var centralVersion) &&
            !string.IsNullOrWhiteSpace(centralVersion))
        {
            return ResolveProperties(centralVersion, properties);
        }

        return "Not specified";
    }

    private static Dictionary<string, string> LoadMsBuildProperties(string projectDirectory, XDocument projectDocument)
    {
        var properties = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        var directoryBuildPropsPath = FindNearestFile(projectDirectory, "Directory.Build.props");
        if (!string.IsNullOrWhiteSpace(directoryBuildPropsPath))
        {
            AddPropertiesFromDocument(properties, LoadXmlDocument(directoryBuildPropsPath));
        }

        var directoryPackagesPropsPath = FindNearestFile(projectDirectory, "Directory.Packages.props");
        if (!string.IsNullOrWhiteSpace(directoryPackagesPropsPath))
        {
            AddPropertiesFromDocument(properties, LoadXmlDocument(directoryPackagesPropsPath));
        }

        AddPropertiesFromDocument(properties, projectDocument);
        return properties;
    }

    private static Dictionary<string, string> LoadCentralPackageVersions(
        string projectDirectory,
        IReadOnlyDictionary<string, string> properties)
    {
        var versions = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        var centralPackagePropsPath = FindNearestFile(projectDirectory, "Directory.Packages.props");
        if (string.IsNullOrWhiteSpace(centralPackagePropsPath))
        {
            return versions;
        }

        var document = LoadXmlDocument(centralPackagePropsPath);
        foreach (var packageVersion in document.Descendants().Where(x => x.Name.LocalName == "PackageVersion"))
        {
            var packageName = packageVersion.Attribute("Include")?.Value?.Trim()
                ?? packageVersion.Attribute("Update")?.Value?.Trim();
            if (string.IsNullOrWhiteSpace(packageName))
            {
                continue;
            }

            var version = packageVersion.Attribute("Version")?.Value?.Trim()
                ?? packageVersion.Elements().FirstOrDefault(x => x.Name.LocalName == "Version")?.Value?.Trim();
            if (string.IsNullOrWhiteSpace(version))
            {
                continue;
            }

            versions[packageName] = ResolveProperties(version, properties);
        }

        return versions;
    }

    private static void AddPropertiesFromDocument(Dictionary<string, string> properties, XDocument document)
    {
        foreach (var propertyGroup in document.Descendants().Where(x => x.Name.LocalName == "PropertyGroup"))
        {
            foreach (var property in propertyGroup.Elements())
            {
                if (!property.HasElements && !string.IsNullOrWhiteSpace(property.Name.LocalName))
                {
                    var value = property.Value?.Trim();
                    if (!string.IsNullOrWhiteSpace(value))
                    {
                        properties[property.Name.LocalName] = ResolveProperties(value, properties);
                    }
                }
            }
        }
    }

    private static string ResolveProperties(string value, IReadOnlyDictionary<string, string> properties)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return value;
        }

        return Regex.Replace(
            value.Trim(),
            @"\$\((?<name>[A-Za-z0-9_.-]+)\)",
            match => properties.TryGetValue(match.Groups["name"].Value, out var replacement)
                ? replacement
                : match.Value);
    }

    private static string? FindNearestFile(string startDirectory, string fileName)
    {
        var directory = new DirectoryInfo(startDirectory);
        while (directory is not null)
        {
            var candidate = Path.Combine(directory.FullName, fileName);
            if (File.Exists(candidate))
            {
                return candidate;
            }

            directory = directory.Parent;
        }

        return null;
    }

    private static XDocument LoadXmlDocument(string filePath)
    {
        try
        {
            return XDocument.Load(filePath, LoadOptions.PreserveWhitespace | LoadOptions.SetLineInfo);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or System.Xml.XmlException)
        {
            throw new InvalidOperationException($"Unable to parse MSBuild props file '{filePath}'.", ex);
        }
    }
}
