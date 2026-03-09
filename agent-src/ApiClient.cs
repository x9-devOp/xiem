using System.Net;
using System.Net.Http.Json;
using System.Text.Json;

namespace XiemAgent;

public class ApiClient
{
    private readonly HttpClient _http;
    private readonly ILogger<ApiClient> _log;
    private readonly IConfiguration _config;

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
            AgentVersion  = "2.0.0"
        };
        try
        {
            var resp = await _http.PostAsJsonAsync("/api/agent/register", req, JsonOpts, ct);
            resp.EnsureSuccessStatusCode();
            return await resp.Content.ReadFromJsonAsync<RegisterResponse>(JsonOpts, ct);
        }
        catch (Exception ex)
        {
            _log.LogError(ex, "Register failed");
            return null;
        }
    }

    public async Task<AgentConfig?> GetConfigAsync(CancellationToken ct)
    {
        SetToken();
        try
        {
            return await _http.GetFromJsonAsync<AgentConfig>("/api/agent/config", JsonOpts, ct);
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
        try { await _http.PostAsync("/api/agent/heartbeat", null, ct); }
        catch (Exception ex) { _log.LogWarning(ex, "Heartbeat failed"); }
    }
}
