using System.Net;
using System.Net.Http.Json;
using System.Text.Json;

namespace XiemAgent;

public class ApiClient
{
    private readonly HttpClient _http;
    private readonly ILogger<ApiClient> _log;
    private readonly IConfiguration _config;

    /// <summary>Updated on every successful server response. Used by PanicWatchdog.</summary>
    public DateTime LastContact { get; private set; } = DateTime.UtcNow;

    private static readonly JsonSerializerOptions JsonOpts = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.SnakeCaseLower
    };

    public ApiClient(HttpClient http, ILogger<ApiClient> log, IConfiguration config)
    {
        _http = http;
        _log = log;
        _config = config;
    }

    private string? Token => _config["Xiem:Token"];

    private void SetToken()
    {
        _http.DefaultRequestHeaders.Remove("X-Agent-Token");
        if (!string.IsNullOrEmpty(Token))
            _http.DefaultRequestHeaders.Add("X-Agent-Token", Token);
    }

    private static string ResolveFqdn()
    {
        try { return Dns.GetHostEntry(Environment.MachineName).HostName; }
        catch { return ""; }
    }

    public async Task<RegisterResponse?> RegisterAsync(CancellationToken ct)
    {
        var req = new RegisterRequest
        {
            InstallSecret = _config["Xiem:InstallSecret"] ?? "",
            Hostname      = Environment.MachineName,
            Fqdn          = ResolveFqdn(),
            Group         = _config["Xiem:Group"] ?? "",
            AgentVersion  = AgentVersion.Current
        };
        try
        {
            var resp = await _http.PostAsJsonAsync("/api/agent/register", req, JsonOpts, ct);
            resp.EnsureSuccessStatusCode();
            LastContact = DateTime.UtcNow;
            return await resp.Content.ReadFromJsonAsync<RegisterResponse>(JsonOpts, ct);
        }
        catch (Exception ex)
        {
            _log.LogError(ex, "Register failed");
            return null;
        }
    }

    public async Task<string?> GetPubKeyAsync(CancellationToken ct)
    {
        try
        {
            var pem = await _http.GetStringAsync("/api/agent/pubkey", ct);
            LastContact = DateTime.UtcNow;
            return pem;
        }
        catch (Exception ex)
        {
            _log.LogWarning(ex, "GetPubKey failed");
            return null;
        }
    }

    public async Task<AgentConfig?> GetConfigAsync(CancellationToken ct)
    {
        SetToken();
        try
        {
            var cfg = await _http.GetFromJsonAsync<AgentConfig>("/api/agent/config", JsonOpts, ct);
            if (cfg != null) LastContact = DateTime.UtcNow;
            return cfg;
        }
        catch (Exception ex)
        {
            _log.LogError(ex, "GetConfig failed");
            return null;
        }
    }

    public async Task<IngestResponse?> IngestAsync(IngestRequest req, CancellationToken ct)
    {
        SetToken();
        try
        {
            var resp = await _http.PostAsJsonAsync("/api/agent/ingest", req, JsonOpts, ct);
            resp.EnsureSuccessStatusCode();
            return await resp.Content.ReadFromJsonAsync<IngestResponse>(JsonOpts, ct);
        }
        catch (Exception ex)
        {
            _log.LogError(ex, "Ingest failed for module {Module}", req.Module);
            return null;
        }
    }

    public async Task HeartbeatAsync(CancellationToken ct)
    {
        SetToken();
        try
        {
            var body = new { version = AgentVersion.Current, fqdn = ResolveFqdn() };
            var resp = await _http.PostAsJsonAsync("/api/agent/heartbeat", body, JsonOpts, ct);
            if (resp.IsSuccessStatusCode) LastContact = DateTime.UtcNow;
        }
        catch (Exception ex) { _log.LogWarning(ex, "Heartbeat failed"); }
    }

    public async Task<List<AgentCommand>> GetCommandsAsync(CancellationToken ct)
    {
        SetToken();
        try
        {
            var result = await _http.GetFromJsonAsync<List<AgentCommand>>("/api/agent/commands", JsonOpts, ct);
            if (result != null) LastContact = DateTime.UtcNow;
            return result ?? new();
        }
        catch (Exception ex)
        {
            _log.LogWarning(ex, "GetCommands failed");
            return new();
        }
    }

    public async Task<byte[]?> DownloadBinaryAsync(string path, CancellationToken ct)
    {
        SetToken();
        try
        {
            var bytes = await _http.GetByteArrayAsync(path, ct);
            LastContact = DateTime.UtcNow;
            return bytes;
        }
        catch (Exception ex)
        {
            _log.LogError(ex, "Failed to download binary from {Path}", path);
            return null;
        }
    }

    public async Task PostCommandResultAsync(CommandResult result, CancellationToken ct)
    {
        SetToken();
        try
        {
            var resp = await _http.PostAsJsonAsync(
                $"/api/agent/commands/{result.CommandId}/result", result, JsonOpts, ct);
            if (!resp.IsSuccessStatusCode)
                _log.LogWarning("PostCommandResult {Id} returned {Status}", result.CommandId, resp.StatusCode);
        }
        catch (Exception ex)
        {
            _log.LogWarning(ex, "PostCommandResult {Id} failed", result.CommandId);
        }
    }
}
