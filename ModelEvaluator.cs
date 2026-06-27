using ClosedXML.Excel;
using System.Text.Json;

namespace GeminiNuGetAuditor;

public static class ModelEvaluator
{
    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        PropertyNameCaseInsensitive = true,
        WriteIndented = true
    };

    public static GeminiResponse LoadCodeBertPredictions(string predictionJsonPath)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(predictionJsonPath);

        if (!File.Exists(predictionJsonPath))
        {
            throw new FileNotFoundException("CodeBERT prediction JSON was not found.", predictionJsonPath);
        }

        var json = File.ReadAllText(predictionJsonPath);
        var response = TryReadPredictionResponse(json);

        if (response.VulnerabilityReports.Count == 0)
        {
            throw new InvalidOperationException("CodeBERT prediction JSON does not contain any VulnerabilityReports.");
        }

        if (string.IsNullOrWhiteSpace(response.ModelName))
        {
            response.ModelName = "codebert-python-bridge";
        }

        return response;
    }

    private static GeminiResponse TryReadPredictionResponse(string json)
    {
        try
        {
            using var document = JsonDocument.Parse(json);
            if (document.RootElement.ValueKind == JsonValueKind.Array)
            {
                return new GeminiResponse
                {
                    VulnerabilityReports = JsonSerializer.Deserialize<List<VulnerabilityReport>>(json, JsonOptions) ?? new List<VulnerabilityReport>()
                };
            }

            if (document.RootElement.ValueKind != JsonValueKind.Object)
            {
                return new GeminiResponse();
            }

            var response = JsonSerializer.Deserialize<GeminiResponse>(json, JsonOptions);
            if (response?.VulnerabilityReports is { Count: > 0 })
            {
                return response;
            }

            foreach (var propertyName in new[] { "VulnerabilityReports", "Predictions", "predictions" })
            {
                if (document.RootElement.TryGetProperty(propertyName, out var property) &&
                    property.ValueKind == JsonValueKind.Array)
                {
                    return new GeminiResponse
                    {
                        ModelName = ReadJsonString(document.RootElement, "ModelName", "modelName"),
                        VulnerabilityReports = JsonSerializer.Deserialize<List<VulnerabilityReport>>(property.GetRawText(), JsonOptions) ?? new List<VulnerabilityReport>()
                    };
                }
            }

            return response ?? new GeminiResponse();
        }
        catch (JsonException ex)
        {
            throw new InvalidOperationException($"CodeBERT prediction JSON is invalid: {ex.Message}", ex);
        }
    }

    private static string ReadJsonString(JsonElement element, params string[] propertyNames)
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

    public static EvaluationMetrics Calculate(
        string scenario,
        IReadOnlyCollection<VulnerabilityReport> predictions,
        IReadOnlyCollection<GroundTruthLabel> groundTruth)
    {
        ArgumentNullException.ThrowIfNull(predictions);
        ArgumentNullException.ThrowIfNull(groundTruth);

        var predictionLookup = predictions
            .Where(x => !string.IsNullOrWhiteSpace(x.PackageName))
            .GroupBy(x => x.PackageName, StringComparer.OrdinalIgnoreCase)
            .ToDictionary(x => x.Key, x => x.First(), StringComparer.OrdinalIgnoreCase);

        var records = groundTruth.Select(label =>
        {
            predictionLookup.TryGetValue(label.PackageName, out var prediction);
            var predicted = prediction?.IsVulnerable ?? false;

            return new EvaluationRecord
            {
                Scenario = scenario,
                PackageName = label.PackageName,
                CurrentVersion = label.CurrentVersion,
                PredictedVulnerable = predicted,
                GroundTruthVulnerable = label.IsVulnerable,
                MatchResult = GetMatchResult(predicted, label.IsVulnerable),
                CVE_ID = prediction?.CVE_ID ?? label.CVE_ID,
                Severity = prediction?.Severity ?? label.Severity,
                IsGroundedInReference = prediction?.IsGroundedInReference ?? false
            };
        }).ToList();

        var truePositive = records.Count(x => x.PredictedVulnerable && x.GroundTruthVulnerable);
        var trueNegative = records.Count(x => !x.PredictedVulnerable && !x.GroundTruthVulnerable);
        var falsePositive = records.Count(x => x.PredictedVulnerable && !x.GroundTruthVulnerable);
        var falseNegative = records.Count(x => !x.PredictedVulnerable && x.GroundTruthVulnerable);
        var total = records.Count;
        var precisionDenominator = truePositive + falsePositive;
        var recallDenominator = truePositive + falseNegative;
        var precision = precisionDenominator > 0 ? (double)truePositive / precisionDenominator : 0d;
        var recall = recallDenominator > 0 ? (double)truePositive / recallDenominator : 0d;

        return new EvaluationMetrics
        {
            Scenario = scenario,
            Total = total,
            TruePositive = truePositive,
            TrueNegative = trueNegative,
            FalsePositive = falsePositive,
            FalseNegative = falseNegative,
            Accuracy = total > 0 ? (double)(truePositive + trueNegative) / total : 0d,
            Precision = precision,
            Recall = recall,
            F1Score = precision + recall > 0 ? 2 * precision * recall / (precision + recall) : 0d,
            FalsePositiveRatio = precisionDenominator > 0 ? (double)falsePositive / precisionDenominator : 0d,
            Records = records
        };
    }

    public static string SaveExcelReport(
        string outputDirectory,
        string projectName,
        IReadOnlyCollection<EvaluationMetrics> metrics)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(outputDirectory);
        ArgumentException.ThrowIfNullOrWhiteSpace(projectName);
        ArgumentNullException.ThrowIfNull(metrics);

        Directory.CreateDirectory(outputDirectory);
        var outputFilePath = Path.Combine(
            outputDirectory,
            $"evaluation-{projectName}-{DateTime.UtcNow:yyyyMMdd-HHmmss}.xlsx");

        using var workbook = new XLWorkbook();
        WriteSummarySheet(workbook, metrics);
        WriteDetailSheet(workbook, metrics.SelectMany(x => x.Records).ToList());
        workbook.SaveAs(outputFilePath);
        return outputFilePath;
    }

    private static void WriteSummarySheet(XLWorkbook workbook, IReadOnlyCollection<EvaluationMetrics> metrics)
    {
        var sheet = workbook.Worksheets.Add("Summary");
        sheet.Cell(1, 1).Value = "Scenario";
        sheet.Cell(1, 2).Value = "Total";
        sheet.Cell(1, 3).Value = "TP";
        sheet.Cell(1, 4).Value = "TN";
        sheet.Cell(1, 5).Value = "FP";
        sheet.Cell(1, 6).Value = "FN";
        sheet.Cell(1, 7).Value = "Accuracy";
        sheet.Cell(1, 8).Value = "Precision";
        sheet.Cell(1, 9).Value = "Recall";
        sheet.Cell(1, 10).Value = "F1-Score";
        sheet.Cell(1, 11).Value = "FP Ratio";

        var row = 2;
        foreach (var metric in metrics)
        {
            sheet.Cell(row, 1).Value = metric.Scenario;
            sheet.Cell(row, 2).Value = metric.Total;
            sheet.Cell(row, 3).Value = metric.TruePositive;
            sheet.Cell(row, 4).Value = metric.TrueNegative;
            sheet.Cell(row, 5).Value = metric.FalsePositive;
            sheet.Cell(row, 6).Value = metric.FalseNegative;
            sheet.Cell(row, 7).Value = metric.Accuracy;
            sheet.Cell(row, 8).Value = metric.Precision;
            sheet.Cell(row, 9).Value = metric.Recall;
            sheet.Cell(row, 10).Value = metric.F1Score;
            sheet.Cell(row, 11).Value = metric.FalsePositiveRatio;
            row++;
        }

        sheet.Range(1, 1, 1, 11).Style.Font.Bold = true;
        sheet.Range(1, 1, 1, 11).Style.Fill.BackgroundColor = XLColor.LightGray;
        if (row > 2)
        {
            sheet.Range(2, 7, row - 1, 11).Style.NumberFormat.Format = "0.00%";
        }

        sheet.SheetView.FreezeRows(1);
        sheet.Range(1, 1, Math.Max(1, row - 1), 11).SetAutoFilter();
        sheet.Columns().AdjustToContents();
    }

    private static void WriteDetailSheet(XLWorkbook workbook, IReadOnlyCollection<EvaluationRecord> records)
    {
        var sheet = workbook.Worksheets.Add("Detail");
        sheet.Cell(1, 1).Value = "Scenario";
        sheet.Cell(1, 2).Value = "PackageName";
        sheet.Cell(1, 3).Value = "CurrentVersion";
        sheet.Cell(1, 4).Value = "PredictedVulnerable";
        sheet.Cell(1, 5).Value = "GroundTruthVulnerable";
        sheet.Cell(1, 6).Value = "MatchResult";
        sheet.Cell(1, 7).Value = "CVE_ID";
        sheet.Cell(1, 8).Value = "Severity";
        sheet.Cell(1, 9).Value = "IsGroundedInReference";

        var row = 2;
        foreach (var record in records)
        {
            sheet.Cell(row, 1).Value = record.Scenario;
            sheet.Cell(row, 2).Value = record.PackageName;
            sheet.Cell(row, 3).Value = record.CurrentVersion;
            sheet.Cell(row, 4).Value = record.PredictedVulnerable;
            sheet.Cell(row, 5).Value = record.GroundTruthVulnerable;
            sheet.Cell(row, 6).Value = record.MatchResult;
            sheet.Cell(row, 7).Value = record.CVE_ID;
            sheet.Cell(row, 8).Value = record.Severity;
            sheet.Cell(row, 9).Value = record.IsGroundedInReference;

            if (record.MatchResult is "False Positive" or "False Negative")
            {
                sheet.Range(row, 1, row, 9).Style.Fill.BackgroundColor = XLColor.LightPink;
            }
            else if (record.MatchResult == "True Positive")
            {
                sheet.Range(row, 1, row, 9).Style.Fill.BackgroundColor = XLColor.LightGoldenrodYellow;
            }

            row++;
        }

        sheet.Range(1, 1, 1, 9).Style.Font.Bold = true;
        sheet.Range(1, 1, 1, 9).Style.Fill.BackgroundColor = XLColor.LightGray;
        sheet.SheetView.FreezeRows(1);
        sheet.Range(1, 1, Math.Max(1, row - 1), 9).SetAutoFilter();
        sheet.Columns().AdjustToContents();
    }

    private static string GetMatchResult(bool predicted, bool groundTruth)
    {
        return (predicted, groundTruth) switch
        {
            (true, true) => "True Positive",
            (false, false) => "True Negative",
            (true, false) => "False Positive",
            _ => "False Negative"
        };
    }
}
