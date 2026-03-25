using System.Text;
using System.Xml.Linq;

namespace GeminiNuGetAuditor;

public static class CsprojPackageExtractor
{
    public static string ExtractPackagesFromCsproj(string filePath)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(filePath);

        var document = XDocument.Load(filePath);

        var packages = document
            .Descendants()
            .Where(x => x.Name.LocalName == "PackageReference")
            .Select(x => new
            {
                Name = x.Attribute("Include")?.Value ?? x.Attribute("Update")?.Value ?? string.Empty,
                Version = x.Attribute("Version")?.Value ?? x.Elements().FirstOrDefault(e => e.Name.LocalName == "Version")?.Value ?? "Not specified"
            })
            .Where(x => !string.IsNullOrWhiteSpace(x.Name))
            .ToList();

        if (packages.Count == 0)
        {
            return "No PackageReference entries were found in the project file.";
        }

        var builder = new StringBuilder();
        builder.AppendLine("NuGet packages found in the project:");

        foreach (var package in packages)
        {
            builder.AppendLine($"- {package.Name}: {package.Version}");
        }

        return builder.ToString().TrimEnd();
    }
}
