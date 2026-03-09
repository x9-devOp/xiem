using System.Diagnostics;
using System.Text;
using System.Text.Json;

namespace XiemAgent;

/// <summary>
/// Caches the server-issued panic command on disk (survives restarts).
/// Monitors connectivity via ApiClient.LastContact.
/// When offline longer than payload["timeout"] -> executes panic script.
/// After reconnect -> clears cache and waits for a new panic command.
/// </summary>
public class PanicWatchdog
{
    private readonly ILogger<PanicWatchdog> _log;
    private readonly ApiClient _api;

    private AgentCommand? _panic;
    private bool _executed;

    private static readonly string CacheFile = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
        "XiemAgent", "panic_command.json");

    public PanicWatchdog(ILogger<PanicWatchdog> log, ApiClient api)
    {
        _log = log;
        _api = api;
    }

    public void Set(AgentCommand cmd)
    {
        _panic   = cmd;
        _executed = false;
        SaveCache(cmd);
        _log.LogInformation("PanicWatchdog: panic command set (timeout={T} retry={R})",
            GetStr(cmd, "timeout", "2h"), GetStr(cmd, "retry_interval", "5m"));
    }

    public void Clear()
    {
        _panic   = null;
        _executed = false;
        TryDelete();
        _log.LogInformation("PanicWatchdog: cleared after server reconnect");
    }

    public async Task RunAsync(CancellationToken ct)
    {
        // Restore from disk so panic survives an agent restart while offline
        if (_panic == null)
        {
            _panic = LoadCache();
            if (_panic != null)
                _log.LogInformation("PanicWatchdog: restored panic command from disk");
        }

        while (!ct.IsCancellationRequested)
        {
            int sleepSec = 30;

            try
            {
                if (_panic != null && !_executed)
                {
                    var timeout = ParseDuration(GetStr(_panic, "timeout", "2h"));
                    var offline = DateTime.UtcNow - _api.LastContact;

                    if (offline > timeout)
                    {
                        _log.LogCritical("PanicWatchdog: offline {Elapsed} > timeout {T} — executing panic",
                            offline, timeout);
                        await ExecuteAsync(_panic, ct);
                        _executed = true;
                        sleepSec  = (int)ParseDuration(GetStr(_panic, "retry_interval", "5m")).TotalSeconds;
                    }
                }
                else if (_executed)
                {
                    // Check if server is reachable again
                    if (DateTime.UtcNow - _api.LastContact < TimeSpan.FromSeconds(90))
                    {
                        _log.LogInformation("PanicWatchdog: reconnected after panic execution — clearing cache");
                        Clear();
                    }
                    else
                    {
                        sleepSec = (int)ParseDuration(GetStr(_panic!, "retry_interval", "5m")).TotalSeconds;
                    }
                }
            }
            catch (OperationCanceledException) { break; }
            catch (Exception ex)
            {
                _log.LogError(ex, "PanicWatchdog tick error");
            }

            try { await Task.Delay(TimeSpan.FromSeconds(sleepSec), ct); }
            catch (OperationCanceledException) { break; }
        }
    }

    private async Task ExecuteAsync(AgentCommand cmd, CancellationToken ct)
    {
        var script = GetStr(cmd, "script", "");
        if (string.IsNullOrWhiteSpace(script))
        {
            _log.LogCritical("PanicWatchdog: panic payload has no script — cannot execute");
            return;
        }

        var encoded = Convert.ToBase64String(Encoding.Unicode.GetBytes(script));
        var psi = new ProcessStartInfo
        {
            FileName      = "powershell.exe",
            Arguments     = $"-NoProfile -NonInteractive -EncodedCommand {encoded}",
            UseShellExecute = false,
            CreateNoWindow  = true,
            RedirectStandardOutput = true,
            RedirectStandardError  = true
        };

        try
        {
            using var proc = Process.Start(psi)
                ?? throw new InvalidOperationException("Failed to start powershell.exe for panic");
            await proc.WaitForExitAsync(ct);
            _log.LogCritical("PanicWatchdog: panic script exited with code {Code}", proc.ExitCode);
        }
        catch (Exception ex)
        {
            _log.LogCritical(ex, "PanicWatchdog: panic script execution failed");
        }
    }

    // --- helpers ---

    private static string GetStr(AgentCommand cmd, string key, string def) =>
        cmd.Payload.TryGetValue(key, out var v) ? v?.ToString() ?? def : def;

    internal static TimeSpan ParseDuration(string s)
    {
        if (string.IsNullOrEmpty(s)) return TimeSpan.FromHours(2);
        var unit = s[^1];
        if (int.TryParse(s[..^1], out var n))
            return unit switch
            {
                's' => TimeSpan.FromSeconds(n),
                'm' => TimeSpan.FromMinutes(n),
                'h' => TimeSpan.FromHours(n),
                'd' => TimeSpan.FromDays(n),
                _   => TimeSpan.FromHours(2)
            };
        return TimeSpan.FromHours(2);
    }

    private void SaveCache(AgentCommand cmd)
    {
        try
        {
            Directory.CreateDirectory(Path.GetDirectoryName(CacheFile)!);
            File.WriteAllText(CacheFile, JsonSerializer.Serialize(cmd));
        }
        catch (Exception ex) { _log.LogWarning(ex, "Failed to save panic cache"); }
    }

    private AgentCommand? LoadCache()
    {
        try
        {
            if (!File.Exists(CacheFile)) return null;
            return JsonSerializer.Deserialize<AgentCommand>(File.ReadAllText(CacheFile));
        }
        catch { return null; }
    }

    private static void TryDelete()
    {
        try { if (File.Exists(CacheFile)) File.Delete(CacheFile); } catch { }
    }
}
