using System.Windows;
using WinShield.Core;

namespace WinShield;

public partial class LoginWindow : Window
{
    private readonly AccountStore _store;
    private string? _pendingUser;

    /// <summary>Name of the signed-in user once the window closes with DialogResult = true.</summary>
    public string? SignedInUser { get; private set; }

    public LoginWindow(AccountStore store)
    {
        InitializeComponent();
        _store = store;
        if (!_store.HasAccounts) ShowCreate(null, null!);      // first run: go straight to sign-up
        Loaded += (_, _) => (SignInPanel.Visibility == Visibility.Visible ? SiUser : CrUser).Focus();
    }

    private void Show(UIElement panel, string subtitle)
    {
        foreach (var p in new UIElement[] { SignInPanel, CreatePanel, ResetPanel, KeyPanel }) p.Visibility = Visibility.Collapsed;
        panel.Visibility = Visibility.Visible;
        Subtitle.Text = subtitle;
        Msg.Text = "";
        Msg.Foreground = new System.Windows.Media.SolidColorBrush(System.Windows.Media.Color.FromRgb(0xF0, 0x60, 0x5F));
    }

    private void ShowSignIn(object? s, RoutedEventArgs e) { Show(SignInPanel, "Sign in to your protection console"); SiUser.Focus(); }
    private void ShowCreate(object? s, RoutedEventArgs e) => Show(CreatePanel, "Create your account");
    private void ShowReset(object? s, RoutedEventArgs e) { Show(ResetPanel, "Reset a forgotten password"); RsUser.Text = SiUser.Text; }

    private void OnSignIn(object s, RoutedEventArgs e)
    {
        var r = _store.SignIn(SiUser.Text, SiPass.Password);
        if (!r.Ok) { Msg.Text = r.Error; SiPass.Clear(); return; }
        Finish(r.Username!);
    }

    private void OnCreate(object s, RoutedEventArgs e)
    {
        var r = _store.Register(CrUser.Text, CrPass.Password, CrConfirm.Password);
        if (!r.Ok) { Msg.Text = r.Error; return; }
        CrPass.Clear(); CrConfirm.Clear();
        ShowKey(r.Username!, r.RecoveryKey!);
    }

    private void OnReset(object s, RoutedEventArgs e)
    {
        var r = _store.ResetPassword(RsUser.Text, RsKey.Text, RsPass.Password, RsConfirm.Password);
        if (!r.Ok) { Msg.Text = r.Error; return; }
        RsKey.Clear(); RsPass.Clear(); RsConfirm.Clear();
        ShowKey(r.Username!, r.RecoveryKey!);
        Subtitle.Text = "Password changed. Here is your NEW recovery key";
    }

    private void ShowKey(string user, string key)
    {
        _pendingUser = user;
        KeyBox.Text = key;
        KeySaved.IsChecked = false;
        Show(KeyPanel, "Account ready");
    }

    private void OnCopyKey(object s, RoutedEventArgs e)
    {
        try { Clipboard.SetText(KeyBox.Text); Msg.Foreground = System.Windows.Media.Brushes.LightGreen; Msg.Text = "Copied."; }
        catch { Msg.Text = "Could not reach the clipboard. Select the key and copy it by hand."; }
    }

    private void OnKeySavedChanged(object s, RoutedEventArgs e) => KeyGo.IsEnabled = KeySaved.IsChecked == true;

    private void OnKeyContinue(object s, RoutedEventArgs e)
    {
        if (_pendingUser != null) Finish(_pendingUser);
    }

    private void Finish(string user)
    {
        SignedInUser = user;
        DialogResult = true;
    }
}
