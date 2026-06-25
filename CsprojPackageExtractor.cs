using System.Text;
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

        return document
            .Descendants()
            .Where(x => x.Name.LocalName == "PackageReference")
            .Select(x => new NuGetPackageReference
            {
                PackageName = ReadPackageName(x),
                CurrentVersion = ReadPackageVersion(x)
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
            ?? element.Attribute("Remove")?.Value?.Trim()
            ?? string.Empty;
    }

    private static string ReadPackageVersion(XElement element)
    {
        var attributeVersion = element.Attribute("Version")?.Value?.Trim();
        if (!string.IsNullOrWhiteSpace(attributeVersion))
        {
            return attributeVersion;
        }

        var childVersion = element.Elements()
            .FirstOrDefault(e => e.Name.LocalName == "Version")
            ?.Value
            ?.Trim();

        return string.IsNullOrWhiteSpace(childVersion) ? "Not specified" : childVersion;
    }
}
