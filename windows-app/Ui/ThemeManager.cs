using System.Windows;
using System.Windows.Media;
using Microsoft.Win32;
using WinShield.Core;

namespace WinShield.Ui;

/// <summary>
/// Light / dark mode. Every colour the console uses is a DynamicResource brush in App.xaml;
/// switching the theme replaces those brushes, so the whole window re-colours instantly.
/// The choice is remembered in %LocalAppData%\WinShield\theme.txt. First run follows the Windows setting.
/// </summary>
public static class ThemeManager
{
    public static bool IsDark { get; private set; }

    private static string FilePath => Path.Combine(AppPaths.Root, "theme.txt");

    // name -> (light, dark)
    private static readonly (string Key, string Light, string Dark)[] Palette =
    {
        ("WindowTop",     "#FFFBEF", "#0A0A0C"),
        ("WindowBottom",  "#FFEDB8", "#1B1507"),
        ("CardBackground","#FFFFFF", "#131316"),
        ("CardBorder",    "#EADFB8", "#2E2A18"),
        ("TextBrush",     "#17140A", "#F6F1E0"),
        ("MutedText",     "#6B6450", "#A9A28A"),
        ("AccentBrush",   "#F5B700", "#FFC933"),
        ("AccentSoft",    "#FFF1B8", "#2B2408"),
        ("InputBackground","#FFFFFF","#0F0F10"),
        ("GridBackground","#FFFDF4", "#0F0F11"),
        ("GridHeader",    "#FFE9A3", "#26200C"),
        ("GridAlt",       "#FFF8DC", "#16150F"),
        ("HoverBrush",    "#FFEFB5", "#2A240F"),
        ("ButtonBackground","#FFFFFF","#1D1B14"),
        ("SafeBrush",     "#2E9D57", "#2FA862"),
        ("DangerBrush",   "#C93C3C", "#D64545"),
        ("OffBrush",      "#C2680A", "#B45309"),
        ("Tile1",         "#2F6FEB", "#5AA2FF"),   // blue
        ("Tile2",         "#7C4DFF", "#A78BFA"),   // violet
        ("Tile3",         "#0FA89A", "#2DD4BF"),   // teal
        ("Tile4",         "#F08A00", "#FF9F43"),   // orange
        ("Tile5",         "#E0457B", "#FF6B9A"),   // rose
        ("Tile6",         "#C99700", "#FFC933"),   // gold
    };

    /// <summary>Call once at start-up, before any window is shown.</summary>
    public static void Init()
    {
        bool dark;
        try
        {
            if (File.Exists(FilePath)) dark = File.ReadAllText(FilePath).Trim().Equals("dark", StringComparison.OrdinalIgnoreCase);
            else dark = SystemPrefersDark();
        }
        catch { dark = true; }
        Apply(dark);
    }

    public static void Toggle()
    {
        Apply(!IsDark);
        try
        {
            Directory.CreateDirectory(AppPaths.Root);
            File.WriteAllText(FilePath, IsDark ? "dark" : "light");
        }
        catch { /* the choice just will not be remembered */ }
    }

    public static void Apply(bool dark)
    {
        IsDark = dark;
        var res = Application.Current.Resources;

        foreach (var (key, light, darkHex) in Palette)
        {
            var c = (Color)ColorConverter.ConvertFromString(dark ? darkHex : light);
            var b = new SolidColorBrush(c);
            b.Freeze();
            res[key] = b;
        }

        // The window backdrop is a soft vertical gradient between two palette colours.
        var top = (Color)ColorConverter.ConvertFromString(Hex("WindowTop", dark));
        var bottom = (Color)ColorConverter.ConvertFromString(Hex("WindowBottom", dark));
        var bg = new LinearGradientBrush(top, bottom, 90);
        bg.Freeze();
        res["WindowBackground"] = bg;
    }

    private static string Hex(string key, bool dark)
    {
        foreach (var p in Palette)
            if (p.Key == key) return dark ? p.Dark : p.Light;
        return "#000000";
    }

    private static bool SystemPrefersDark()
    {
        try
        {
            using var k = Registry.CurrentUser.OpenSubKey(@"Software\Microsoft\Windows\CurrentVersion\Themes\Personalize");
            return k?.GetValue("AppsUseLightTheme") is int v && v == 0;
        }
        catch { return true; }
    }
}
