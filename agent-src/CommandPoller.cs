using System.Diagnostics;
using System.Text;

namespace XiemAgent;

/// <summary>
/// Polls /api/agent/commands every 30 seconds, executes powershell/cmd commands,
/// posts results back. Panic and update commands are handled in later phases.
/// </summary>
public class CommandPoller
{
    private readonly ILogger<CommandPoller> _log;
    private readonly ApiClient _api;
    private readonly IConfiguration _config;

    private static readonly TimeSpan PollInterval = TimeSpan.FromSeconds(30);
    private const int DefaultTimeoutSec = 60;

    public CommandPoller(ILogger<CommandPoller> log, ApiClient api, IConfiguration config)
    {
        _log = log;
        _api = api;
        _config = config;
    }

    public async Task RunAsync(CancellationToken ct)
    {
        _log.LogInformation("CommandPoller starting (interval={Interval}s)", PollInterval.TotalSeconds);

        while (!ct.IsCancellationRequested)
        {
            try
            {
                var commands = await _api.GetCommandsAsync(ct);
                foreach (var cmd in commands)
                {
                    if (ct.IsCancellationRequested) break;
                    await ExecuteCommandAsync(cmd, ct);
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

    private async Task ExecuteCommandAsync(AgentCommand cmd, CancellationToken ct)
    {
        _log.LogInformation("Executing command {Id} type={Type}", cmd.Id, cmd.CommandType);

        CommandResult result;
        switch (cmd.CommandType)
        {
            case "powershell":
                result = await RunPowershellAsync(cmd, ct);
                break;
            case "cmd":
                result = await RunCmdAsync(cmd, ct);
                break;
            case "update":
                _log.LogWarning("Command {Id}: update not yet implemented (Phase 6)", cmd.Id);
                result = new CommandResult { CommandId = cmd.Id, Output = "update: not implemented", ExitCode = -1 };
                break;
            case "panic":
                _log.LogWarning("Command {Id}: panic not yet implemented (Phase 4)", cmd.Id);
                result = new CommandResult { CommandId = cmd.Id, Output = "panic: not implemented", ExitCode = -1 };
                break;
            default:
                _log.LogWarning("Command {Id}: unknown type {Type}", cmd.Id, cmd.CommandType);
                result = new CommandResult { CommandId = cmd.Id, Output = $"unknown command type: {cmd.CommandType}", ExitCode = -1 };
                break;
        }

        await _api.PostCommandResultAsync(result, ct);
    }

    private async Task<CommandResult> RunPowershellAsync(AgentCommand cmd, CancellationToken ct)
    {
        var script = GetScript(cmd);
        if (script == null)
            return new CommandResult { CommandId = cmd.Id, Error = "missing script in payload", ExitCode = -1 };

        var timeoutSec = GetTimeout(cmd);
        var encoded = Convert.ToBase64String(Encoding.Unicode.GetBytes(script));

        return await RunProcessAsync(cmd.Id, "powershell.exe",
            $"-NoProfile -NonInteractive -EncodedCommand {encoded}",
            timeoutSec, ct);
    }

    private async Task<CommandResult> RunCmdAsync(AgentCommand cmd, CancellationToken ct)
    {
        var script = GetScript(cmd);
        if (script == null)
            return new CommandResult { CommandId = cmd.Id, Error = "missing script in payload", ExitCode = -1 };

        var timeoutSec = GetTimeout(cmd);
        return await RunProcessAsync(cmd.Id, "cmd.exe", $"/c {script}", timeoutSec, ct);
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

            _log.LogInformation("Command {Id} completed, exit={Code}, output_len={Len}",
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
