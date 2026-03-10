using System.Diagnostics;
using System.Text;

namespace XiemAgent;

/// <summary>
/// Polls /api/agent/commands every 30 seconds.
/// All commands are RSA-PSS verified before execution.
/// panic -> handed to PanicWatchdog (not executed directly).
/// update -> stubbed until Phase 6.
/// </summary>
public class CommandPoller
{
    private readonly ILogger<CommandPoller> _log;
    private readonly ApiClient _api;
    private readonly SignatureVerifier _verifier;
    private readonly PanicWatchdog _watchdog;

    private static readonly TimeSpan PollInterval = TimeSpan.FromSeconds(30);
    private const int DefaultTimeoutSec = 60;

    public CommandPoller(ILogger<CommandPoller> log, ApiClient api,
                         SignatureVerifier verifier, PanicWatchdog watchdog)
    {
        _log      = log;
        _api      = api;
        _verifier = verifier;
        _watchdog = watchdog;
    }

    public async Task RunAsync(CancellationToken ct)
    {
        _log.LogInformation("CommandPoller starting (interval={Interval}s)", PollInterval.TotalSeconds);

        while (!ct.IsCancellationRequested)
        {
            try
            {
                // If pubkey is missing (e.g. server was unreachable at startup), retry download.
                if (!_verifier.IsLoaded)
                {
                    var pem = await _api.GetPubKeyAsync(ct);
                    if (pem != null) _verifier.LoadFromPem(pem);
                }

                var commands = await _api.GetCommandsAsync(ct);
                foreach (var cmd in commands)
                {
                    if (ct.IsCancellationRequested) break;
                    await HandleCommandAsync(cmd, ct);
                }
            }
            catch (OperationCanceledException) { break; }
            catch (Exception ex)
            {
                _log.LogError(ex, "CommandPoller iteration failed");
            }

            try { await Task.Delay(PollInterval, ct); }
            catch (OperationCanceledException) { break; }
        }

        _log.LogInformation("CommandPoller stopped");
    }

    private async Task HandleCommandAsync(AgentCommand cmd, CancellationToken ct)
    {
        // Verify signature before doing anything else
        if (!_verifier.Verify(cmd.Id, cmd.CommandType, cmd.Payload, cmd.Signature))
        {
            _log.LogWarning("Command {Id} rejected: invalid or missing signature", cmd.Id);
            await _api.PostCommandResultAsync(new CommandResult
            {
                CommandId = cmd.Id, ExitCode = -1, Error = "signature verification failed"
            }, ct);
            return;
        }

        _log.LogInformation("Command {Id} type={Type} — signature OK", cmd.Id, cmd.CommandType);

        CommandResult result;
        switch (cmd.CommandType)
        {
            case "powershell":
                result = await RunPowershellAsync(cmd, ct);
                break;
            case "cmd":
                result = await RunCmdAsync(cmd, ct);
                break;
            case "panic":
                _watchdog.Set(cmd);
                result = new CommandResult { CommandId = cmd.Id, Output = "panic command cached", ExitCode = 0 };
                break;
            case "update":
                result = await RunUpdateAsync(cmd, ct);
                break;
            default:
                _log.LogWarning("Command {Id}: unknown type {Type}", cmd.Id, cmd.CommandType);
                result = new CommandResult { CommandId = cmd.Id, Error = $"unknown command type: {cmd.CommandType}", ExitCode = -1 };
                break;
        }

        await _api.PostCommandResultAsync(result, ct);
    }

    private async Task<CommandResult> RunPowershellAsync(AgentCommand cmd, CancellationToken ct)
    {
        var script = GetScript(cmd);
        if (script == null)
            return new CommandResult { CommandId = cmd.Id, Error = "missing script in payload", ExitCode = -1 };

        var encoded = Convert.ToBase64String(Encoding.Unicode.GetBytes(script));
        return await RunProcessAsync(cmd.Id, "powershell.exe",
            $"-NoProfile -NonInteractive -EncodedCommand {encoded}",
            GetTimeout(cmd), ct);
    }

    private async Task<CommandResult> RunCmdAsync(AgentCommand cmd, CancellationToken ct)
    {
        var script = GetScript(cmd);
        if (script == null)
            return new CommandResult { CommandId = cmd.Id, Error = "missing script in payload", ExitCode = -1 };

        return await RunProcessAsync(cmd.Id, "cmd.exe", $"/c {script}", GetTimeout(cmd), ct);
    }

    private async Task<CommandResult> RunProcessAsync(
        int cmdId, string exe, string args, int timeoutSec, CancellationToken ct)
    {
        var psi = new ProcessStartInfo
        {
            FileName               = exe,
            Arguments              = args,
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
                ?? throw new InvalidOperationException($"Failed to start {exe}");

            var stdoutTask = proc.StandardOutput.ReadToEndAsync(cts.Token);
            var stderrTask = proc.StandardError.ReadToEndAsync(cts.Token);
            await proc.WaitForExitAsync(cts.Token);

            var stdout = await stdoutTask;
            var stderr = await stderrTask;

            var output = stdout.TrimEnd();
            if (!string.IsNullOrWhiteSpace(stderr))
                output += (output.Length > 0 ? "\n" : "") + "[stderr]\n" + stderr.TrimEnd();

            _log.LogInformation("Command {Id} exit={Code} output_len={Len}",
                cmdId, proc.ExitCode, output.Length);

            return new CommandResult
            {
                CommandId = cmdId,
                Output    = output.Length > 0 ? output : null,
                ExitCode  = proc.ExitCode
            };
        }
        catch (OperationCanceledException)
        {
            _log.LogWarning("Command {Id} timed out after {Sec}s", cmdId, timeoutSec);
            return new CommandResult { CommandId = cmdId, Error = $"timed out after {timeoutSec}s", ExitCode = -1 };
        }
        catch (Exception ex)
        {
            _log.LogError(ex, "Command {Id} execution failed", cmdId);
            return new CommandResult { CommandId = cmdId, Error = ex.Message, ExitCode = -1 };
        }
    }

    private async Task<CommandResult> RunUpdateAsync(AgentCommand cmd, CancellationToken ct)
    {
        var currentExe = Environment.ProcessPath;
        if (string.IsNullOrEmpty(currentExe))
            return new CommandResult { CommandId = cmd.Id, Error = "Cannot determine executable path", ExitCode = -1 };

        var tempExe    = currentExe + ".new";
        var scriptPath = Path.Combine(Path.GetTempPath(), "xiem_update.ps1");
        var errorLog   = Path.Combine(Path.GetTempPath(), "xiem_update_error.txt");

        _log.LogInformation("Update {Id}: downloading new binary", cmd.Id);
        var bytes = await _api.DownloadBinaryAsync("/api/download/agent", ct);
        if (bytes == null || bytes.Length == 0)
            return new CommandResult { CommandId = cmd.Id, Error = "Failed to download new binary", ExitCode = -1 };

        try { await File.WriteAllBytesAsync(tempExe, bytes, ct); }
        catch (Exception ex)
        {
            return new CommandResult { CommandId = cmd.Id, Error = $"Failed to save binary: {ex.Message}", ExitCode = -1 };
        }

        // Updater runs detached: waits 3s (so result gets posted), stops service,
        // replaces binary, starts service.
        // Uses @-string + Replace to avoid conflicts between PS $_ / {{ and C# interpolation.
        var script = @"Start-Sleep -Seconds 3
try {
    Stop-Service -Name 'XiemAgent' -Force -ErrorAction Stop
    Start-Sleep -Seconds 2
    Copy-Item -Path 'TEMP_EXE' -Destination 'CURRENT_EXE' -Force
    Remove-Item -Path 'TEMP_EXE' -ErrorAction SilentlyContinue
    Start-Service -Name 'XiemAgent'
} catch {
    $_ | Out-File -FilePath 'ERROR_LOG' -Force
}
Remove-Item -Path 'SCRIPT_PATH' -ErrorAction SilentlyContinue"
            .Replace("TEMP_EXE",    tempExe)
            .Replace("CURRENT_EXE", currentExe)
            .Replace("ERROR_LOG",   errorLog)
            .Replace("SCRIPT_PATH", scriptPath);

        try { await File.WriteAllTextAsync(scriptPath, script, ct); }
        catch (Exception ex)
        {
            return new CommandResult { CommandId = cmd.Id, Error = $"Failed to write updater script: {ex.Message}", ExitCode = -1 };
        }

        // UseShellExecute=true creates a detached process that survives service stop
        var encoded = Convert.ToBase64String(Encoding.Unicode.GetBytes($"& '{scriptPath}'"));
        try
        {
            Process.Start(new ProcessStartInfo
            {
                FileName        = "powershell.exe",
                Arguments       = $"-NoProfile -NonInteractive -WindowStyle Hidden -EncodedCommand {encoded}",
                UseShellExecute = true
            });
        }
        catch (Exception ex)
        {
            return new CommandResult { CommandId = cmd.Id, Error = $"Failed to launch updater: {ex.Message}", ExitCode = -1 };
        }

        _log.LogInformation("Update {Id}: updater launched ({Bytes} B), service restarts in ~5s",
            cmd.Id, bytes.Length);
        return new CommandResult
        {
            CommandId = cmd.Id,
            Output    = $"Update initiated. Binary: {bytes.Length:N0} B. Service restarting in ~5s.",
            ExitCode  = 0
        };
    }

    private static string? GetScript(AgentCommand cmd) =>
        cmd.Payload.TryGetValue("script", out var v) ? v?.ToString() : null;

    private static int GetTimeout(AgentCommand cmd)
    {
        if (cmd.Payload.TryGetValue("timeout_sec", out var v) &&
            int.TryParse(v?.ToString(), out var t) && t > 0)
            return t;
        return DefaultTimeoutSec;
    }
}
