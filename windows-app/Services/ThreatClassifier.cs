using System.Text.Json;
using WinShield.Core;

namespace WinShield.Services;

/// <summary>
/// Optional machine-learning layer: a logistic-regression model trained offline by tools/train_model.py.
/// Features are log(1 + count) values from the detection window. Without a model file the classifier is
/// simply off and the rule engine works on its own.
/// </summary>
public sealed class ThreatClassifier
{
    public static readonly string[] FeatureNames =
        { "modified", "renamed", "extChanged", "suspiciousExt", "highEntropy", "deleted", "dirs", "notes", "honeypot" };

    private double _bias;
    private Dictionary<string, double> _weights = new();

    public bool Available { get; private set; }
    public string Description { get; private set; } = "Not loaded (rules only)";

    public void Load(string? path = null)
    {
        path ??= AppPaths.ModelFile;
        Available = false;
        Description = "Not loaded (rules only)";

        try
        {
            if (!File.Exists(path)) return;

            using var doc = JsonDocument.Parse(File.ReadAllText(path));
            var root = doc.RootElement;

            _bias = root.GetProperty("bias").GetDouble();
            _weights = new Dictionary<string, double>();
            foreach (var prop in root.GetProperty("weights").EnumerateObject())
                _weights[prop.Name] = prop.Value.GetDouble();

            var trainedOn = root.TryGetProperty("trained_on", out var t) ? t.GetString() : "unknown data";
            Available = _weights.Count > 0;
            Description = Available ? $"Loaded ({_weights.Count} features, trained on {trainedOn})" : Description;
        }
        catch (Exception ex)
        {
            Description = $"Model could not be loaded: {ex.Message}";
        }
    }

    /// <summary>Probability that the window looks like ransomware, scaled to 0-100.</summary>
    public double Score(IReadOnlyDictionary<string, double> features)
    {
        if (!Available) return 0;

        var z = _bias;
        foreach (var (name, weight) in _weights)
        {
            if (features.TryGetValue(name, out var x))
                z += weight * Math.Log(1 + Math.Max(0, x));
        }

        return 100.0 / (1.0 + Math.Exp(-z));
    }
}
