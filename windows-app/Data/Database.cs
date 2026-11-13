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

    public static void Initialize()
    {
        var schemaPath = Path.Combine(AppContext.BaseDirectory, "Data", "schema.sql");
        var schema = File.ReadAllText(schemaPath);

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
