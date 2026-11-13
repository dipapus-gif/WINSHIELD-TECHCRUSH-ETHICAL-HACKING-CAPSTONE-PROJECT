using System.Globalization;
using System.Windows;
using System.Windows.Data;
using System.Windows.Media;
using WinShield.Models;

namespace WinShield;

public sealed class StatusToBrushConverter : IValueConverter
{
    private static readonly Brush Green = Freeze(new SolidColorBrush(Color.FromRgb(0x2E, 0x9D, 0x57)));
    private static readonly Brush Amber = Freeze(new SolidColorBrush(Color.FromRgb(0xD9, 0x8E, 0x04)));
    private static readonly Brush Red = Freeze(new SolidColorBrush(Color.FromRgb(0xC9, 0x3C, 0x3C)));
    private static readonly Brush Gray = Freeze(new SolidColorBrush(Color.FromRgb(0x6B, 0x72, 0x80)));

    public object Convert(object value, Type targetType, object parameter, CultureInfo culture) =>
        value is CheckStatus status
            ? status switch
            {
                CheckStatus.Pass => Green,
                CheckStatus.Warning => Amber,
                CheckStatus.Fail => Red,
                _ => Gray
            }
            : Gray;

    public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture) =>
        throw new NotSupportedException();

    private static Brush Freeze(SolidColorBrush b)
    {
        b.Freeze();
        return b;
    }
}

/// <summary>Colours an incident severity (Severity enum) or a threat level word (Quiet, Elevated, High, Critical).</summary>
public sealed class SeverityToBrushConverter : IValueConverter
{
    private static readonly StatusToBrushConverter Inner = new();

    public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
    {
        var status = (value?.ToString() ?? "") switch
        {
            "Critical" or "High" => CheckStatus.Fail,
            "Medium" or "Elevated" => CheckStatus.Warning,
            "Low" or "Quiet" => CheckStatus.Pass,
            _ => CheckStatus.Info
        };
        return Inner.Convert(status, targetType, parameter, culture);
    }

    public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture) =>
        throw new NotSupportedException();
}

/// <summary>True hides the element, false shows it. Used for "not running as administrator" notices.</summary>
public sealed class InverseBoolToVisibilityConverter : IValueConverter
{
    public object Convert(object value, Type targetType, object parameter, CultureInfo culture) =>
        value is true ? Visibility.Collapsed : Visibility.Visible;

    public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture) =>
        throw new NotSupportedException();
}

public sealed class ScoreToBrushConverter : IValueConverter
{
    private static readonly StatusToBrushConverter Inner = new();

    public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
    {
        var score = value is int i ? i : 0;
        var status = score >= 75 ? CheckStatus.Pass : score >= 50 ? CheckStatus.Warning : CheckStatus.Fail;
        return Inner.Convert(status, targetType, parameter, culture);
    }

    public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture) =>
        throw new NotSupportedException();
}
