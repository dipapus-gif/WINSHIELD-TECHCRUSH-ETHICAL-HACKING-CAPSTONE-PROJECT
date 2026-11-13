using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace WinShield.Core;

/// <summary>Result of an account operation. <see cref="Error"/> is null on success.</summary>
public sealed record AccountResult(bool Ok, string? Error, string? RecoveryKey = null, string? Username = null);

/// <summary>
/// On-device accounts. Nothing leaves the computer: passwords and recovery keys are stored only as
/// salted PBKDF2-SHA256 hashes in %LocalAppData%\WinShield\accounts.json.
/// Forgotten password: the recovery key shown once at sign-up (and after every reset) proves ownership.
/// </summary>
public sealed class AccountStore
{
    public const int MinPassword = 8;
    private const int Iterations = 210_000;
    private const int MaxFailures = 5;
    private static readonly TimeSpan LockFor = TimeSpan.FromMinutes(5);

    private sealed class Account
    {
        public string Username { get; set; } = "";
        public string Salt { get; set; } = "";
        public string Hash { get; set; } = "";
        public string RecoverySalt { get; set; } = "";
        public string RecoveryHash { get; set; } = "";
        public DateTime CreatedUtc { get; set; }
        public DateTime? LastLoginUtc { get; set; }
        public int Failures { get; set; }
        public DateTime? LockedUntilUtc { get; set; }
    }

    private readonly string _file;
    private readonly object _gate = new();
    private List<Account> _accounts = new();

    public AccountStore(string? file = null)
    {
        _file = file ?? Path.Combine(AppPaths.Root, "accounts.json");
        Load();
    }

    public bool HasAccounts { get { lock (_gate) return _accounts.Count > 0; } }

    // ------------------------------------------------------------------ validation

    public static string? ValidateUsername(string? username)
    {
        if (string.IsNullOrWhiteSpace(username)) return "Enter a username.";
        username = username.Trim();
        if (username.Length < 3 || username.Length > 24) return "Username must be 3 to 24 characters.";
        foreach (var c in username)
            if (!(char.IsAsciiLetterOrDigit(c) || c is '_' or '.' or '-'))
                return "Username can use letters, numbers, dot, dash and underscore only.";
        return null;
    }

    public static string? ValidatePassword(string? password, string? username = null)
    {
        if (string.IsNullOrEmpty(password) || password.Length < MinPassword) return $"Password must be at least {MinPassword} characters.";
        if (!password.Any(char.IsLetter) || !password.Any(char.IsDigit)) return "Password needs at least one letter and one number.";
        if (!string.IsNullOrEmpty(username) && password.Contains(username, StringComparison.OrdinalIgnoreCase))
            return "Password must not contain your username.";
        return null;
    }

    // ------------------------------------------------------------------ operations

    public AccountResult Register(string? username, string? password, string? confirm)
    {
        var e = ValidateUsername(username);
        if (e != null) return Fail(e);
        username = username!.Trim();
        e = ValidatePassword(password, username);
        if (e != null) return Fail(e);
        if (password != confirm) return Fail("The two passwords do not match.");

        lock (_gate)
        {
            if (Find(username) != null) return Fail("That username is already taken.");
            var key = NewRecoveryKey();
            var acct = new Account { Username = username, CreatedUtc = DateTime.UtcNow };
            SetPassword(acct, password!);
            SetRecovery(acct, key);
            _accounts.Add(acct);
            Save();
            return new AccountResult(true, null, key, acct.Username);
        }
    }

    public AccountResult SignIn(string? username, string? password)
    {
        lock (_gate)
        {
            var a = Find(username);
            // Same message for unknown user and wrong password, so usernames cannot be probed.
            const string bad = "Wrong username or password.";
            if (a == null) { Burn(password); return Fail(bad); }

            if (a.LockedUntilUtc is { } until && until > DateTime.UtcNow)
                return Fail($"Too many attempts. Try again in {Math.Ceiling((until - DateTime.UtcNow).TotalMinutes)} minute(s), or reset your password with your recovery key.");

            if (!Verify(password ?? "", a.Salt, a.Hash))
            {
                a.Failures++;
                if (a.Failures >= MaxFailures) { a.LockedUntilUtc = DateTime.UtcNow + LockFor; a.Failures = 0; }
                Save();
                return Fail(bad);
            }

            a.Failures = 0; a.LockedUntilUtc = null; a.LastLoginUtc = DateTime.UtcNow;
            Save();
            return new AccountResult(true, null, null, a.Username);
        }
    }

    /// <summary>Forgotten password. Needs the recovery key; returns a NEW recovery key (the old one stops working).</summary>
    public AccountResult ResetPassword(string? username, string? recoveryKey, string? newPassword, string? confirm)
    {
        lock (_gate)
        {
            var a = Find(username);
            const string bad = "Username or recovery key is not correct.";
            if (a == null) { Burn(recoveryKey); return Fail(bad); }

            if (a.LockedUntilUtc is { } until && until > DateTime.UtcNow)
                return Fail($"Too many attempts. Try again in {Math.Ceiling((until - DateTime.UtcNow).TotalMinutes)} minute(s).");

            if (!Verify(NormalizeKey(recoveryKey), a.RecoverySalt, a.RecoveryHash))
            {
                a.Failures++;
                if (a.Failures >= MaxFailures) { a.LockedUntilUtc = DateTime.UtcNow + LockFor; a.Failures = 0; }
                Save();
                return Fail(bad);
            }

            var e = ValidatePassword(newPassword, a.Username);
            if (e != null) return Fail(e);
            if (newPassword != confirm) return Fail("The two passwords do not match.");

            var key = NewRecoveryKey();
            SetPassword(a, newPassword!);
            SetRecovery(a, key);
            a.Failures = 0; a.LockedUntilUtc = null;
            Save();
            return new AccountResult(true, null, key, a.Username);
        }
    }

    public AccountResult ChangePassword(string username, string? current, string? newPassword, string? confirm)
    {
        lock (_gate)
        {
            var a = Find(username);
            if (a == null || !Verify(current ?? "", a.Salt, a.Hash)) return Fail("Current password is not correct.");
            var e = ValidatePassword(newPassword, a.Username);
            if (e != null) return Fail(e);
            if (newPassword != confirm) return Fail("The two passwords do not match.");
            SetPassword(a, newPassword!);
            Save();
            return new AccountResult(true, null, null, a.Username);
        }
    }

    // ------------------------------------------------------------------ internals

    private static AccountResult Fail(string e) => new(false, e);
    private Account? Find(string? u) => string.IsNullOrWhiteSpace(u) ? null
        : _accounts.FirstOrDefault(a => a.Username.Equals(u.Trim(), StringComparison.OrdinalIgnoreCase));

    private static void SetPassword(Account a, string password)
    {
        var salt = RandomNumberGenerator.GetBytes(16);
        a.Salt = Convert.ToBase64String(salt);
        a.Hash = Convert.ToBase64String(Derive(password, salt));
    }

    private static void SetRecovery(Account a, string key)
    {
        var salt = RandomNumberGenerator.GetBytes(16);
        a.RecoverySalt = Convert.ToBase64String(salt);
        a.RecoveryHash = Convert.ToBase64String(Derive(NormalizeKey(key), salt));
    }

    private static byte[] Derive(string secret, byte[] salt) =>
        Rfc2898DeriveBytes.Pbkdf2(Encoding.UTF8.GetBytes(secret), salt, Iterations, HashAlgorithmName.SHA256, 32);

    private static bool Verify(string secret, string saltB64, string hashB64)
    {
        try
        {
            var actual = Derive(secret, Convert.FromBase64String(saltB64));
            return CryptographicOperations.FixedTimeEquals(actual, Convert.FromBase64String(hashB64));
        }
        catch { return false; }
    }

    /// <summary>Spend the same time as a real check so an unknown username is not distinguishable by speed.</summary>
    private static void Burn(string? s) => Derive(s ?? "", new byte[16]);

    private static string NormalizeKey(string? k) =>
        new string((k ?? "").Where(char.IsLetterOrDigit).ToArray()).ToUpperInvariant();

    /// <summary>20 characters from an unambiguous alphabet, shown as XXXXX-XXXXX-XXXXX-XXXXX (about 100 bits).</summary>
    public static string NewRecoveryKey()
    {
        const string alphabet = "ABCDEFGHJKMNPQRSTUVWXYZ23456789";
        var sb = new StringBuilder();
        for (int i = 0; i < 20; i++)
        {
            if (i > 0 && i % 5 == 0) sb.Append('-');
            sb.Append(alphabet[RandomNumberGenerator.GetInt32(alphabet.Length)]);
        }
        return sb.ToString();
    }

    private void Load()
    {
        try
        {
            if (File.Exists(_file))
                _accounts = JsonSerializer.Deserialize<List<Account>>(File.ReadAllText(_file)) ?? new();
        }
        catch { _accounts = new(); }
    }

    private void Save()
    {
        Directory.CreateDirectory(Path.GetDirectoryName(_file)!);
        var tmp = _file + ".tmp";
        File.WriteAllText(tmp, JsonSerializer.Serialize(_accounts, new JsonSerializerOptions { WriteIndented = true }));
        File.Move(tmp, _file, overwrite: true);
    }
}
