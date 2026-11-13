using System.Globalization;
using Microsoft.Data.Sqlite;
using WinShield.Models;

namespace WinShield.Data;

/// <summary>Storage for file events, incidents, baselines, honeypots, quarantine and recovery points.</summary>
public sealed class ProtectionRepository
{
    private const int MaxFileEventRows = 100_000;

    private static string Iso(DateTime d) => d.ToUniversalTime().ToString("o");

    private static DateTime ParseIso(string s) =>
        DateTime.Parse(s, CultureInfo.InvariantCulture, DateTimeStyles.RoundtripKind);

    private static void Bind(SqliteCommand cmd, (string Name, object? Value)[] ps)
    {
        foreach (var (name, value) in ps)
            cmd.Parameters.AddWithValue(name, value ?? DBNull.Value);
    }

    private static int Exec(string sql, params (string Name, object? Value)[] ps)
    {
        using var conn = Database.Open();
        using var cmd = conn.CreateCommand();
        cmd.CommandText = sql;
        Bind(cmd, ps);
        return cmd.ExecuteNonQuery();
    }

    private static long Insert(string sql, params (string Name, object? Value)[] ps)
    {
        using var conn = Database.Open();
        using var cmd = conn.CreateCommand();
        cmd.CommandText = sql + "; SELECT last_insert_rowid();";
        Bind(cmd, ps);
        return (long)cmd.ExecuteScalar()!;
    }

    private static List<T> Query<T>(string sql, Func<SqliteDataReader, T> map, params (string Name, object? Value)[] ps)
    {
        var list = new List<T>();
        using var conn = Database.Open();
        using var cmd = conn.CreateCommand();
        cmd.CommandText = sql;
        Bind(cmd, ps);
        using var reader = cmd.ExecuteReader();
        while (reader.Read()) list.Add(map(reader));
        return list;
    }

    private static string? NullableString(SqliteDataReader r, int i) => r.IsDBNull(i) ? null : r.GetString(i);

    // ------------------------------------------------------------------
    // File events
    // ------------------------------------------------------------------

    public void LogFileEvents(IReadOnlyCollection<FileActivity> events)
    {
        if (events.Count == 0) return;
        using var conn = Database.Open();
        using var tx = conn.BeginTransaction();
        foreach (var e in events)
        {
            using var cmd = conn.CreateCommand();
            cmd.Transaction = tx;
            cmd.CommandText = @"INSERT INTO file_events (time_utc, kind, path, old_path, size, entropy, is_honeypot)
                                VALUES ($t, $k, $p, $o, $s, $e, $h);";
            Bind(cmd, new (string, object?)[]
            {
                ("$t", Iso(e.TimeUtc)), ("$k", e.Kind.ToString()), ("$p", e.FilePath), ("$o", e.OldPath),
                ("$s", e.Size), ("$e", e.Entropy), ("$h", e.IsHoneypot ? 1 : 0)
            });
            cmd.ExecuteNonQuery();
        }

        using (var prune = conn.CreateCommand())
        {
            prune.Transaction = tx;
            prune.CommandText = "DELETE FROM file_events WHERE id <= (SELECT MAX(id) FROM file_events) - $max;";
            prune.Parameters.AddWithValue("$max", MaxFileEventRows);
            prune.ExecuteNonQuery();
        }
        tx.Commit();
    }

    public List<FileActivity> GetRecentFileEvents(int limit)
    {
        var rows = Query(
            @"SELECT time_utc, kind, path, old_path, size, entropy, is_honeypot
              FROM file_events ORDER BY id DESC LIMIT $n;",
            r => new FileActivity(
                ParseIso(r.GetString(0)), Enum.Parse<FileEventKind>(r.GetString(1)), r.GetString(2),
                NullableString(r, 3), r.GetInt64(4), r.GetDouble(5), r.GetInt32(6) == 1),
            ("$n", limit));
        rows.Reverse();
        return rows;
    }

    // ------------------------------------------------------------------
    // Incidents
    // ------------------------------------------------------------------

    private static Incident MapIncident(SqliteDataReader r) => new()
    {
        Id = r.GetInt64(0),
        TimeUtc = ParseIso(r.GetString(1)),
        Severity = Enum.Parse<Severity>(r.GetString(2)),
        Score = r.GetDouble(3),
        Title = r.GetString(4),
        Description = r.GetString(5),
        RuleIds = r.GetString(6),
        ProcessId = r.IsDBNull(7) ? null : r.GetInt32(7),
        ProcessName = NullableString(r, 8),
        ProcessPath = NullableString(r, 9),
        Attribution = r.GetString(10),
        Status = r.GetString(11),
        ResolvedUtc = r.IsDBNull(12) ? null : ParseIso(r.GetString(12)),
        EvidencePath = NullableString(r, 13),
        AffectedCount = r.GetInt32(14)
    };

    private const string IncidentColumns =
        "id, time_utc, severity, score, title, description, rule_ids, process_id, process_name, process_path, " +
        "attribution, status, resolved_utc, evidence_path, affected_count";

    public long AddIncident(DetectionResult d)
    {
        return Insert(
            @"INSERT INTO incidents (time_utc, severity, score, title, description, rule_ids,
                                     process_id, process_name, process_path, attribution, affected_count)
              VALUES ($t, $sev, $score, $title, $desc, $rules, $pid, $pname, $ppath, $attr, $n)",
            ("$t", Iso(d.TimeUtc)), ("$sev", d.Severity.ToString()), ("$score", d.Score),
            ("$title", d.Title), ("$desc", d.Description), ("$rules", string.Join(",", d.RuleIds)),
            ("$pid", d.ProcessId), ("$pname", d.ProcessName), ("$ppath", d.ProcessPath),
            ("$attr", d.Attribution), ("$n", d.AffectedFiles.Count));
    }

    public void UpdateIncident(Incident i)
    {
        Exec(
            @"UPDATE incidents SET severity = $sev, score = $score, title = $title, description = $desc,
                                   rule_ids = $rules, process_id = $pid, process_name = $pname,
                                   process_path = $ppath, attribution = $attr, affected_count = $n
              WHERE id = $id;",
            ("$sev", i.Severity.ToString()), ("$score", i.Score), ("$title", i.Title), ("$desc", i.Description),
            ("$rules", i.RuleIds), ("$pid", i.ProcessId), ("$pname", i.ProcessName), ("$ppath", i.ProcessPath),
            ("$attr", i.Attribution), ("$n", i.AffectedCount), ("$id", i.Id));
    }

    public void AddIncidentFiles(long incidentId, IEnumerable<string> paths, string reason)
    {
        using var conn = Database.Open();
        using var tx = conn.BeginTransaction();
        foreach (var p in paths)
        {
            using var cmd = conn.CreateCommand();
            cmd.Transaction = tx;
            cmd.CommandText = "INSERT OR IGNORE INTO incident_files (incident_id, path, reason) VALUES ($i, $p, $r);";
            cmd.Parameters.AddWithValue("$i", incidentId);
            cmd.Parameters.AddWithValue("$p", p);
            cmd.Parameters.AddWithValue("$r", reason);
            cmd.ExecuteNonQuery();
        }
        tx.Commit();
    }

    public int CountIncidentFiles(long incidentId) =>
        Query("SELECT COUNT(*) FROM incident_files WHERE incident_id = $i;", r => r.GetInt32(0), ("$i", incidentId))
            .FirstOrDefault();

    public void SetIncidentStatus(long id, string status)
    {
        var resolved = status is "Resolved" or "FalsePositive" ? Iso(DateTime.UtcNow) : null;
        Exec("UPDATE incidents SET status = $s, resolved_utc = $r WHERE id = $id;",
            ("$s", status), ("$r", resolved), ("$id", id));
    }

    public void SetIncidentEvidence(long id, string path) =>
        Exec("UPDATE incidents SET evidence_path = $p WHERE id = $id;", ("$p", path), ("$id", id));

    public List<Incident> GetIncidents(int limit = 200) =>
        Query($"SELECT {IncidentColumns} FROM incidents ORDER BY time_utc DESC LIMIT $n;", MapIncident, ("$n", limit));

    public List<Incident> GetIncidentsSince(DateTime sinceUtc) =>
        Query($"SELECT {IncidentColumns} FROM incidents WHERE time_utc >= $s ORDER BY time_utc DESC;",
            MapIncident, ("$s", Iso(sinceUtc)));

    public Incident? GetIncident(long id) =>
        Query($"SELECT {IncidentColumns} FROM incidents WHERE id = $id;", MapIncident, ("$id", id)).FirstOrDefault();

    public List<string> GetIncidentFiles(long id, int limit = 2000) =>
        Query("SELECT path FROM incident_files WHERE incident_id = $i ORDER BY id LIMIT $n;",
            r => r.GetString(0), ("$i", id), ("$n", limit));

    public void AddAction(IncidentAction a) =>
        Exec(@"INSERT INTO incident_actions (incident_id, time_utc, action, detail, success)
               VALUES ($i, $t, $a, $d, $s);",
            ("$i", a.IncidentId), ("$t", Iso(a.TimeUtc)), ("$a", a.Action), ("$d", a.Detail), ("$s", a.Success ? 1 : 0));

    public List<IncidentAction> GetActions(long incidentId) =>
        Query(@"SELECT incident_id, time_utc, action, detail, success
                FROM incident_actions WHERE incident_id = $i ORDER BY id;",
            r => new IncidentAction
            {
                IncidentId = r.GetInt64(0),
                TimeUtc = ParseIso(r.GetString(1)),
                Action = r.GetString(2),
                Detail = r.GetString(3),
                Success = r.GetInt32(4) == 1
            },
            ("$i", incidentId));

    public ProtectionStats GetStats()
    {
        var since30 = Iso(DateTime.UtcNow.AddDays(-30));
        var since24 = Iso(DateTime.UtcNow.AddHours(-24));

        int Count(string sql, params (string, object?)[] ps) => Query(sql, r => r.GetInt32(0), ps).FirstOrDefault();

        return new ProtectionStats(
            Count("SELECT COUNT(*) FROM incidents;"),
            Count("SELECT COUNT(*) FROM incidents WHERE status IN ('Open', 'Contained');"),
            Count("SELECT COUNT(*) FROM incidents WHERE severity = 'Critical' AND time_utc >= $s;", ("$s", since30)),
            Count("SELECT COUNT(*) FROM incidents WHERE severity = 'High' AND time_utc >= $s;", ("$s", since30)),
            Count("SELECT COUNT(*) FROM file_events WHERE time_utc >= $s;", ("$s", since24)));
    }

    // ------------------------------------------------------------------
    // Integrity baseline
    // ------------------------------------------------------------------

    public void ReplaceBaseline(IReadOnlyCollection<BaselineEntry> entries)
    {
        using var conn = Database.Open();
        using var tx = conn.BeginTransaction();
        using (var del = conn.CreateCommand())
        {
            del.Transaction = tx;
            del.CommandText = "DELETE FROM integrity_baseline;";
            del.ExecuteNonQuery();
        }

        var now = Iso(DateTime.UtcNow);
        foreach (var e in entries)
        {
            using var cmd = conn.CreateCommand();
            cmd.Transaction = tx;
            cmd.CommandText = @"INSERT OR REPLACE INTO integrity_baseline (path, sha256, size, last_write_utc, baseline_utc)
                                VALUES ($p, $h, $s, $w, $b);";
            cmd.Parameters.AddWithValue("$p", e.FilePath);
            cmd.Parameters.AddWithValue("$h", e.Sha256);
            cmd.Parameters.AddWithValue("$s", e.Size);
            cmd.Parameters.AddWithValue("$w", Iso(e.LastWriteUtc));
            cmd.Parameters.AddWithValue("$b", now);
            cmd.ExecuteNonQuery();
        }
        tx.Commit();
    }

    public Dictionary<string, BaselineEntry> GetBaseline()
    {
        var rows = Query("SELECT path, sha256, size, last_write_utc FROM integrity_baseline;",
            r => new BaselineEntry(r.GetString(0), r.GetString(1), r.GetInt64(2), ParseIso(r.GetString(3))));
        return rows.ToDictionary(e => e.FilePath, StringComparer.OrdinalIgnoreCase);
    }

    public (int Count, DateTime? CreatedUtc) GetBaselineInfo()
    {
        var rows = Query("SELECT COUNT(*), MAX(baseline_utc) FROM integrity_baseline;",
            r => (r.GetInt32(0), r.IsDBNull(1) ? (DateTime?)null : ParseIso(r.GetString(1))));
        return rows.FirstOrDefault();
    }

    // ------------------------------------------------------------------
    // Honeypots
    // ------------------------------------------------------------------

    public void AddHoneypot(string path, string sha256, string folder) =>
        Exec(@"INSERT OR REPLACE INTO honeypots (path, sha256, folder, created_utc) VALUES ($p, $h, $f, $c);",
            ("$p", path), ("$h", sha256), ("$f", folder), ("$c", Iso(DateTime.UtcNow)));

    public void RemoveHoneypot(string path) => Exec("DELETE FROM honeypots WHERE path = $p;", ("$p", path));

    public List<HoneypotFile> GetHoneypots() =>
        Query("SELECT path, sha256, folder, created_utc FROM honeypots ORDER BY path;",
            r => new HoneypotFile
            {
                FilePath = r.GetString(0),
                Sha256 = r.GetString(1),
                Folder = r.GetString(2),
                CreatedUtc = ParseIso(r.GetString(3))
            });

    // ------------------------------------------------------------------
    // Quarantine
    // ------------------------------------------------------------------

    public long AddQuarantine(QuarantineItem q) =>
        Insert(@"INSERT INTO quarantine (original_path, quarantine_path, sha256, time_utc, incident_id, reason)
                 VALUES ($o, $q, $h, $t, $i, $r)",
            ("$o", q.OriginalPath), ("$q", q.QuarantinePath), ("$h", q.Sha256), ("$t", Iso(q.TimeUtc)),
            ("$i", q.IncidentId), ("$r", q.Reason));

    public List<QuarantineItem> GetQuarantine() =>
        Query(@"SELECT id, original_path, quarantine_path, sha256, time_utc, incident_id, reason, restored
                FROM quarantine ORDER BY id DESC;",
            r => new QuarantineItem
            {
                Id = r.GetInt64(0),
                OriginalPath = r.GetString(1),
                QuarantinePath = r.GetString(2),
                Sha256 = r.GetString(3),
                TimeUtc = ParseIso(r.GetString(4)),
                IncidentId = r.IsDBNull(5) ? null : r.GetInt64(5),
                Reason = r.GetString(6),
                Restored = r.GetInt32(7) == 1
            });

    public void MarkQuarantineRestored(long id) => Exec("UPDATE quarantine SET restored = 1 WHERE id = $id;", ("$id", id));

    public void DeleteQuarantine(long id) => Exec("DELETE FROM quarantine WHERE id = $id;", ("$id", id));

    // ------------------------------------------------------------------
    // Recovery points
    // ------------------------------------------------------------------

    public long AddRecoveryPoint(RecoveryPoint rp) =>
        Insert(@"INSERT INTO recovery_points (time_utc, label, folder, file_count, total_bytes, verified)
                 VALUES ($t, $l, $f, $c, $b, $v)",
            ("$t", Iso(rp.TimeUtc)), ("$l", rp.Label), ("$f", rp.Folder), ("$c", rp.FileCount),
            ("$b", rp.TotalBytes), ("$v", rp.Verified ? 1 : 0));

    public List<RecoveryPoint> GetRecoveryPoints() =>
        Query("SELECT id, time_utc, label, folder, file_count, total_bytes, verified FROM recovery_points ORDER BY id DESC;",
            r => new RecoveryPoint
            {
                Id = r.GetInt64(0),
                TimeUtc = ParseIso(r.GetString(1)),
                Label = r.GetString(2),
                Folder = r.GetString(3),
                FileCount = r.GetInt32(4),
                TotalBytes = r.GetInt64(5),
                Verified = r.GetInt32(6) == 1
            });

    public void SetRecoveryPointVerified(long id, bool verified) =>
        Exec("UPDATE recovery_points SET verified = $v WHERE id = $id;", ("$v", verified ? 1 : 0), ("$id", id));

    public void RemoveRecoveryPoint(long id) => Exec("DELETE FROM recovery_points WHERE id = $id;", ("$id", id));
}
