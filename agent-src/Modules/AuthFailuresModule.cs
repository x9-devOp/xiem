using System.Diagnostics.Eventing.Reader;
using System.Text.RegularExpressions;
using System.Xml.Linq;

namespace XiemAgent.Modules;

/// <summary>
/// Collects Windows Event 4625 (failed logon) + correlates with IIS logs for RDWeb IP resolution.
/// </summary>
public class AuthFailuresModule : IModule
{
    private readonly ILogger<AuthFailuresModule> _log;

    public string Name => "auth_failures";

    private static readonly string StateFile =
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
                     "XiemAgent", "auth_failures_lastrun.txt");

    public AuthFailuresModule(ILogger<AuthFailuresModule> log) => _log = log;

    public async Task<List<Dictionary<string, object?>>> CollectAsync(ModuleConfig config, CancellationToken ct)
    {
        var records = new List<Dictionary<string, object?>>();
        var iisLogPath = config.GetString("iis_log_path", @"C:\inetpub\logs\LogFiles\W3SVC1");
        int sleepIisSec = config.GetInt("sleep_iis_sec", 60);

        await Task.Delay(TimeSpan.FromSeconds(sleepIisSec), ct);

        var since = LoadLastRun();
        var events = ReadEvents4625(since);

        if (events.Count == 0)
        {
            _log.LogInformation("AuthFailures: no new events since {Since}", since);
            return records;
        }

        var iisIndex = BuildIisIndex(iisLogPath, since);
        DateTime maxTime = since;

        foreach (var ev in events)
        {
            ct.ThrowIfCancellationRequested();

            var ts = ev.TimeCreated ?? DateTime.UtcNow;
            if (ts > maxTime) maxTime = ts;

            string? ip = ev.Ip;
            if (string.IsNullOrEmpty(ip) || ip == "-")
            {
                ip = ResolveIisIp(iisIndex, ts, toleranceSec: 10);
                if (ip == null) continue;
            }

            records.Add(new Dictionary<string, object?>
            {
                ["datum"]         = ts.ToString("yyyy-MM-dd"),
                ["cas"]           = ts.ToString("HH:mm:ss"),
                ["uzivatel"]      = ev.UserName,
                ["accountdomain"] = ev.Domain,
                ["ipadresa"]      = ip,
                ["pocitac"]       = ev.WorkstationName,
                ["logontype"]     = ev.LogonType,
                ["mistologinu"]   = ev.LogonProcessName,
                ["status"]        = ev.Status,
                ["substatus"]     = ev.SubStatus,
                ["proces"]        = ev.ProcessName,
                ["workstation"]   = ev.WorkstationName,
                ["logonprocess"]  = ev.LogonProcessName,
                ["authpackage"]   = ev.AuthPackage,
                ["sourcedomain"]  = ev.Domain
            });
        }

        if (records.Count > 0) SaveLastRun(maxTime);

        _log.LogInformation("AuthFailures: {Count} records from {Total} events", records.Count, events.Count);
        return records;
    }

    private List<Event4625> ReadEvents4625(DateTime since)
    {
        var result = new List<Event4625>();
        var sinceStr = since.ToUniversalTime().ToString("o");
        var query = new EventLogQuery(
            "Security", PathType.LogName,
            $"*[System[EventID=4625 and TimeCreated[@SystemTime>='{sinceStr}']]]"
        );
        try
        {
            using var reader = new EventLogReader(query);
            EventRecord? record;
            while ((record = reader.ReadEvent()) != null)
                using (record) { result.Add(ParseEvent(record)); }
        }
        catch (Exception ex) { _log.LogError(ex, "Failed to read Security event log"); }
        return result;
    }

    private static Event4625 ParseEvent(EventRecord record)
    {
        var xml = XDocument.Parse(record.ToXml());
        var ns = xml.Root!.Name.Namespace;
        var data = xml.Descendants(ns + "Data")
                      .ToDictionary(e => e.Attribute("Name")?.Value ?? "", e => e.Value);
        return new Event4625
        {
            TimeCreated      = record.TimeCreated?.ToUniversalTime(),
            UserName         = data.GetValueOrDefault("TargetUserName"),
            Domain           = data.GetValueOrDefault("TargetDomainName"),
            Ip               = data.GetValueOrDefault("IpAddress"),
            WorkstationName  = data.GetValueOrDefault("WorkstationName"),
            LogonType        = data.GetValueOrDefault("LogonType"),
            LogonProcessName = data.GetValueOrDefault("LogonProcessName"),
            Status           = data.GetValueOrDefault("Status"),
            SubStatus        = data.GetValueOrDefault("SubStatus"),
            ProcessName      = data.GetValueOrDefault("ProcessName"),
            AuthPackage      = data.GetValueOrDefault("AuthenticationPackageName")
        };
    }

    private Dictionary<DateTime, string> BuildIisIndex(string logPath, DateTime since)
    {
        var index = new Dictionary<DateTime, string>();
        if (!Directory.Exists(logPath)) return index;
        var loginRegex = new Regex(
            @"^(\d{4}-\d{2}-\d{2}\s\d{2}:\d{2}:\d{2})\s+\S+\s+POST\s+/RDWeb/Pages/.*/login\.aspx\s+.*?\s+([\d\.]+)\s",
            RegexOptions.Compiled);
        foreach (var file in Directory.GetFiles(logPath, "u_ex*.log").OrderByDescending(f => f))
        {
            try
            {
                foreach (var line in File.ReadLines(file))
                {
                    if (line.StartsWith("#")) continue;
                    var m = loginRegex.Match(line);
                    if (!m.Success) continue;
                    if (DateTime.TryParse(m.Groups[1].Value, out var ts))
                    {
                        ts = DateTime.SpecifyKind(ts, DateTimeKind.Utc);
                        if (ts < since) break;
                        index.TryAdd(ts, m.Groups[2].Value);
                    }
                }
            }
            catch { }
        }
        return index;
    }

    private static string? ResolveIisIp(Dictionary<DateTime, string> index, DateTime eventTime, int toleranceSec) =>
        index.Where(kv => Math.Abs((kv.Key - eventTime).TotalSeconds) <= toleranceSec)
             .OrderBy(kv => Math.Abs((kv.Key - eventTime).TotalSeconds))
             .Select(kv => kv.Value)
             .FirstOrDefault();

    private DateTime LoadLastRun()
    {
        try
        {
            if (File.Exists(StateFile) && DateTime.TryParse(File.ReadAllText(StateFile).Trim(), out var dt))
                return dt;
        }
        catch { }
        return DateTime.UtcNow.AddDays(-1);
    }

    private void SaveLastRun(DateTime dt)
    {
        try
        {
            Directory.CreateDirectory(Path.GetDirectoryName(StateFile)!);
            File.WriteAllText(StateFile, dt.ToString("o"));
        }
        catch (Exception ex) { _log.LogWarning(ex, "Failed to save last run state"); }
    }

    private class Event4625
    {
        public DateTime? TimeCreated { get; set; }
        public string? UserName { get; set; }
        public string? Domain { get; set; }
        public string? Ip { get; set; }
        public string? WorkstationName { get; set; }
        public string? LogonType { get; set; }
        public string? LogonProcessName { get; set; }
        public string? Status { get; set; }
        public string? SubStatus { get; set; }
        public string? ProcessName { get; set; }
        public string? AuthPackage { get; set; }
    }
}
