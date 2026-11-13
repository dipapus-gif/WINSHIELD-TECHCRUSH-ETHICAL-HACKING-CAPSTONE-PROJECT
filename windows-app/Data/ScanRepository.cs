using Microsoft.Data.Sqlite;
using WinShield.Models;

namespace WinShield.Data;

/// <summary>Stores system-posture scan history in the shared WinShield database.</summary>
public sealed class ScanRepository
{
    // Shares the one WinShield database (and its busy timeout) with the protection repository.
    private static SqliteConnection Open() => Database.Open();

    public void Initialize() => Database.Initialize();

    public long SaveScan(ScanRecord scan, IEnumerable<CheckResult> results)
    {
        using var conn = Open();
        using var tx = conn.BeginTransaction();

        long scanId;
        using (var cmd = conn.CreateCommand())
        {
            cmd.Transaction = tx;
            cmd.CommandText = @"
                INSERT INTO scans (started_utc, machine_name, score, pass_count, warn_count, fail_count)
                VALUES ($started, $machine, $score, $pass, $warn, $fail);
                SELECT last_insert_rowid();";
            cmd.Parameters.AddWithValue("$started", scan.StartedUtc.ToString("o"));
            cmd.Parameters.AddWithValue("$machine", scan.MachineName);
            cmd.Parameters.AddWithValue("$score", scan.Score);
            cmd.Parameters.AddWithValue("$pass", scan.PassCount);
            cmd.Parameters.AddWithValue("$warn", scan.WarnCount);
            cmd.Parameters.AddWithValue("$fail", scan.FailCount);
            scanId = (long)cmd.ExecuteScalar()!;
        }

        foreach (var r in results)
        {
            using var cmd = conn.CreateCommand();
            cmd.Transaction = tx;
            cmd.CommandText = @"
                INSERT INTO check_results (scan_id, check_id, title, status, detail, recommendation)
                VALUES ($scan, $check, $title, $status, $detail, $rec);";
            cmd.Parameters.AddWithValue("$scan", scanId);
            cmd.Parameters.AddWithValue("$check", r.Id);
            cmd.Parameters.AddWithValue("$title", r.Title);
            cmd.Parameters.AddWithValue("$status", r.Status.ToString());
            cmd.Parameters.AddWithValue("$detail", r.Detail);
            cmd.Parameters.AddWithValue("$rec", r.Recommendation);
            cmd.ExecuteNonQuery();
        }

        tx.Commit();
        return scanId;
    }

    public List<ScanRecord> GetHistory(int limit = 50)
    {
        var list = new List<ScanRecord>();
        using var conn = Open();
        using var cmd = conn.CreateCommand();
        cmd.CommandText = @"
            SELECT id, started_utc, machine_name, score, pass_count, warn_count, fail_count
            FROM scans ORDER BY started_utc DESC LIMIT $limit;";
        cmd.Parameters.AddWithValue("$limit", limit);

        using var reader = cmd.ExecuteReader();
        while (reader.Read())
        {
            list.Add(new ScanRecord
            {
                Id = reader.GetInt64(0),
                StartedUtc = DateTime.Parse(reader.GetString(1), null, System.Globalization.DateTimeStyles.RoundtripKind),
                MachineName = reader.GetString(2),
                Score = reader.GetInt32(3),
                PassCount = reader.GetInt32(4),
                WarnCount = reader.GetInt32(5),
                FailCount = reader.GetInt32(6)
            });
        }
        return list;
    }

    public List<CheckResult> GetResults(long scanId)
    {
        var list = new List<CheckResult>();
        using var conn = Open();
        using var cmd = conn.CreateCommand();
        cmd.CommandText = @"
            SELECT check_id, title, status, detail, recommendation
            FROM check_results WHERE scan_id = $scan ORDER BY id;";
        cmd.Parameters.AddWithValue("$scan", scanId);

        using var reader = cmd.ExecuteReader();
        while (reader.Read())
        {
            list.Add(new CheckResult(
                reader.GetString(0),
                reader.GetString(1),
                Enum.Parse<CheckStatus>(reader.GetString(2)),
                reader.GetString(3),
                reader.GetString(4)));
        }
        return list;
    }

    public void DeleteScan(long scanId)
    {
        using var conn = Open();
        using var cmd = conn.CreateCommand();
        cmd.CommandText = "DELETE FROM scans WHERE id = $id;";
        cmd.Parameters.AddWithValue("$id", scanId);
        cmd.ExecuteNonQuery();
    }
}
