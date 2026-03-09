using System.Diagnostics;
using System.Text;
using System.Text.Json;

namespace XiemAgent.Modules;

/// <summary>
/// Generic PowerShell script module. Runs parametry["script"] as Base64-encoded command,
/// expects JSON array on stdout, applies field_mapping, returns records for ingest.
/// </summary>
public class ScriptModule
{
    private readonly ILogger<ScriptModule> _log;

    public ScriptModule(ILogger<ScriptModule> log) => _log = log;

    public async Task<List<Dictionary<string, object?>>> CollectAsync(ModuleConfig config, CancellationToken ct)
    {
        var script = config.GetString("script");
        if (string.IsNullOrWhiteSpace(script))
        {
            _log.LogWarning("ScriptModule [{Name}]: no script configured", config.Name);
            return new();
        }

        int timeoutSec  = config.GetInt("timeout_sec", 30);
        var fieldMapping = GetFieldMapping(config);

        var output = await RunPowershellAsync(config.Name, script, timeoutSec, ct);
        if (output == null) return new();

        return ParseAndMap(output, fieldMapping, config.Name);
    }

    private Dictionary<string, string> GetFieldMapping(ModuleConfig config)
    {
        var result = new Dictionary<string, string>();
        if (!config.Params.TryGetValue("field_mapping", out var raw)) return result;

        JsonElement el;
        if (raw is JsonElement je)
            el = je;
        else if (raw is string s)
        {
            try { el = JsonSerializer.Deserialize<JsonElement>(s); }
            catch { return result; }
        }
        else return result;

        if (el.ValueKind != JsonValueKind.Object) return result;
        foreach (var prop in el.EnumerateObject())
            result[prop.Name] = prop.Value.GetString() ?? prop.Name;

        return result;
    }

    private async Task<string?> RunPowershellAsync(string moduleName, string script, int timeoutSec, CancellationToken ct)
    {
        // Encode script to avoid quoting issues
        var encoded = Convert.ToBase64String(Encoding.Unicode.GetBytes(script));
        var psi = new ProcessStartInfo
        {
            FileName               = "powershell.exe",
            Arguments              = $"-NoProfile -NonInteractive -EncodedCommand {encoded}",
            RedirectStandardOutput = true,
            RedirectStandardError  = true,
            UseShellExecute        = false,
            CreateNoWindow         = true
        };

        using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        cts.CancelAfter(TimeSpan.FromSeconds(timeoutSec));

        try
        {
            using var proc = Process.Start(psi)
                ?? throw new InvalidOperationException("Failed to start powershell.exe");

            var stdoutTask = proc.StandardOutput.ReadToEndAsync(cts.Token);
            var stderrTask = proc.StandardError.ReadToEndAsync(cts.Token);

            await proc.WaitForExitAsync(cts.Token);
            var stdout = await stdoutTask;
            var stderr = await stderrTask;

            if (!string.IsNullOrWhiteSpace(stderr))
                _log.LogWarning("Module [{Name}] ps stderr: {Err}", moduleName, stderr.Trim());

            if (proc.ExitCode != 0)
                _log.LogWarning("Module [{Name}] ps exit code: {Code}", moduleName, proc.ExitCode);

            return stdout;
        }
        catch (OperationCanceledException)
        {
            _log.LogWarning("Module [{Name}] script timed out after {Sec}s", moduleName, timeoutSec);
            return null;
        }
        catch (Exception ex)
        {
            _log.LogError(ex, "Module [{Name}] script execution failed", moduleName);
            return null;
        }
    }

    private List<Dictionary<string, object?>> ParseAndMap(string json, Dictionary<string, string> fieldMapping, string moduleName)
    {
        var result = new List<Dictionary<string, object?>>();
        var trimmed = json.Trim();
        if (string.IsNullOrEmpty(trimmed)) return result;

        try
        {
            var arr = JsonSerializer.Deserialize<JsonElement[]>(trimmed);
            if (arr == null) return result;

            foreach (var el in arr)
            {
                if (el.ValueKind != JsonValueKind.Object) continue;
                var record = new Dictionary<string, object?>();
                foreach (var prop in el.EnumerateObject())
                {
                    var key = fieldMapping.TryGetValue(prop.Name, out var mapped) ? mapped : prop.Name;
                    record[key] = prop.Value.ValueKind switch
                    {
                        JsonValueKind.String  => prop.Value.GetString(),
                        JsonValueKind.Number  => prop.Value.TryGetInt64(out var l) ? (object?)l : prop.Value.GetDouble(),
                        JsonValueKind.True    => (object?)true,
                        JsonValueKind.False   => (object?)false,
                        JsonValueKind.Null    => null,
                        _                     => prop.Value.GetRawText()
                    };
                }
                result.Add(record);
            }
        }
        catch (Exception ex)
        {
            _log.LogError(ex, "Module [{Name}]: failed to parse JSON output", moduleName);
        }

        return result;
    }
}
