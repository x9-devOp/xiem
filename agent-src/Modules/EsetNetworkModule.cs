using System.Diagnostics;
using System.Text.RegularExpressions;

namespace XiemAgent.Modules;

/// <summary>
/// Collects ESET Network Protection blocks via eShell CLI.
/// </summary>
public class EsetNetworkModule : IModule
{
    private readonly ILogger<EsetNetworkModule> _log;

    private static readonly string[] PrivateRanges =
    [
        "10.", "172.16.", "172.17.", "172.18.", "172.19.", "172.20.", "172.21.",
        "172.22.", "172.23.", "172.24.", "172.25.", "172.26.", "172.27.", "172.28.",
        "172.29.", "172.30.", "172.31.", "192.168.", "127.", "::1", "fe80:"
    ];

    // eShell output format: date/time | IP | action | status | protocol
    // Example: "3/2/2026 5:37:37 PM | 1.2.3.4 | Blocked | ..."
    private static readonly Regex LineRegex = new(
        @"^(\d{1,2}/\d{1,2}/\d{4}\s+\d{1,2}:\d{2}:\d{2}\s+[AP]M)\s*\|\s*([\d\.]+)\s*\|\s*(\S+.*?)\s*\|\s*(\S+.*?)\s*\|\s*(\S+)",
        RegexOptions.Compiled | RegexOptions.IgnoreCase
    );

    public string Name => "eset_network";

    public EsetNetworkModule(ILogger<EsetNetworkModule> log) => _log = log;

    public async Task<List<Dictionary<string, object?>>> CollectAsync(ModuleConfig config, CancellationToken ct)
    {
        int windowDays = config.GetInt("window_days", 30);
        var records = new List<Dictionary<string, object?>>();

        string eshellOutput;
        try
        {
            eshellOutput = await RunEshellAsync(windowDays, ct);
        }
        catch (Exception ex)
        {
            _log.LogError(ex, "eShell execution failed");
            return records;
        }

        string? currentIp = null;
        DateTime? currentTs = null;
        string? currentAction = null;
        string? currentStatus = null;
        string? currentProtocol = null;

        foreach (var line in eshellOutput.Split('\n'))
        {
            var trimmed = line.Trim();
            if (string.IsNullOrEmpty(trimmed)) continue;

            var match = LineRegex.Match(trimmed);
            if (match.Success)
            {
                if (TryParseEsetDate(match.Groups[1].Value.Trim(), out var ts))
                {
                    currentTs       = ts;
                    currentIp       = match.Groups[2].Value.Trim();
                    currentAction   = match.Groups[3].Value.Trim();
                    currentStatus   = match.Groups[4].Value.Trim();
                    currentProtocol = match.Groups[5].Value.Trim();
                }
            }
            else if (currentTs.HasValue && IsPublicIp(trimmed) && currentIp != null)
            {
                // Continuation line with attacker IP
                if (!IsPrivate(trimmed))
                {
                    records.Add(new Dictionary<string, object?>
                    {
                        ["cas_udalosti"] = currentTs.Value.ToString("o"),
                        ["ipadresa"]     = trimmed,
                        ["akce"]         = currentAction,
                        ["status"]       = currentStatus,
                        ["protokol"]     = currentProtocol
                    });
                    currentTs = null;
                }
            }
        }

        _log.LogInformation("EsetNetwork: collected {Count} records (window={Days}d)", records.Count, windowDays);
        return records;
    }

    private static bool IsPublicIp(string s)
    {
        var parts = s.Split('.');
        return parts.Length == 4 && parts.All(p => byte.TryParse(p, out _));
    }

    private static async Task<string> RunEshellAsync(int windowDays, CancellationToken ct)
    {
        const string eshell = @"C:\Program Files\ESET\ESET Security\eShell.exe";
        var from = DateTime.Now.AddDays(-windowDays);
        var args = $"get logs network --from \"{from:M/d/yyyy} 0:0:0\" --output plain";

        var psi = new ProcessStartInfo(eshell, args)
        {
            RedirectStandardOutput = true,
            RedirectStandardError  = true,
            UseShellExecute        = false,
            CreateNoWindow         = true
        };

        using var proc = Process.Start(psi)
            ?? throw new InvalidOperationException("Failed to start eShell");

        var output = await proc.StandardOutput.ReadToEndAsync(ct);
        await proc.WaitForExitAsync(ct);
        return output;
    }

    private static bool IsPrivate(string ip) =>
        PrivateRanges.Any(prefix => ip.StartsWith(prefix, StringComparison.OrdinalIgnoreCase));

    private static bool TryParseEsetDate(string s, out DateTime result) =>
        DateTime.TryParseExact(
            s,
            new[] { "M/d/yyyy h:mm:ss tt", "M/d/yyyy hh:mm:ss tt" },
            System.Globalization.CultureInfo.InvariantCulture,
            System.Globalization.DateTimeStyles.None,
            out result
        );
}
