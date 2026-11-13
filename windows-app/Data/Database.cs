using Microsoft.Data.Sqlite;
using WinShield.Core;

namespace WinShield.Data;

/// <summary>Shared SQLite connection factory for all repositories.</summary>
public static class Database
{
    private static readonly string ConnectionString = $"Data Source={AppPaths.Database};Default Timeout=30";

    public static SqliteConnection Open()
    {
        AppPaths.EnsureAll();
        var conn = new SqliteConnection(ConnectionString);
        conn.Open();
        using var pragma = conn.CreateCommand();
        pragma.CommandText = "PRAGMA foreign_keys = ON; PRAGMA busy_timeout = 30000;";
        pragma.ExecuteNonQuery();
        return conn;
    }

    /// <summary>The schema is compiled into the program, so it works wherever the .exe is copied to.</summary>
    private static string LoadSchema()
    {
        var asm = typeof(Database).Assembly;
        using var stream = asm.GetManifestResourceStream("WinShield.schema.sql");
        if (stream != null)
        {
            using var reader = new StreamReader(stream);
            return reader.ReadToEnd();
        }
        // Fallback for builds that did not embed it (the test project).
        return File.ReadAllText(Path.Combine(AppContext.BaseDirectory, "Data", "schema.sql"));
    }

    public static void Initialize()
    {
        var schema = LoadSchema();

        using var conn = Open();
        using (var wal = conn.CreateCommand())
        {
            wal.CommandText = "PRAGMA journal_mode = WAL;";
            wal.ExecuteNonQuery();
        }

        using var cmd = conn.CreateCommand();
        cmd.CommandText = schema;
        cmd.ExecuteNonQuery();
    }
}
