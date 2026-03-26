using System.Text;
using System.Xml.Linq;

namespace GeminiNuGetAuditor;

public static class CsprojPackageExtractor
{
    public static IReadOnlyList<NuGetPackageReference> ExtractPackageReferences(string filePath)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(filePath);

        var document = XDocument.Load(filePath);

        return document
            .Descendants()
            .Where(x => x.Name.LocalName == "PackageReference")
            .Select(x => new NuGetPackageReference
            {
                PackageName = x.Attribute("Include")?.Value ?? x.Attribute("Update")?.Value ?? string.Empty,
                CurrentVersion = x.Attribute("Version")?.Value ?? x.Elements().FirstOrDefault(e => e.Name.LocalName == "Version")?.Value ?? "Not specified"
            })
            .Where(x => !string.IsNullOrWhiteSpace(x.PackageName))
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
}
