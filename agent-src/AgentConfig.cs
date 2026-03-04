namespace XiemAgent;

public class AgentConfig
{
    public int IntervalSec { get; set; } = 3600;
    public List<ModuleConfig> Modules { get; set; } = new();
}

public class ModuleConfig
{
    public string Name { get; set; } = "";
    public bool Enabled { get; set; }
    public int IntervalSec { get; set; } = 3600;
    public Dictionary<string, object?> Params { get; set; } = new();

    public string GetString(string key, string defaultValue = "") =>
        Params.TryGetValue(key, out var v) ? v?.ToString() ?? defaultValue : defaultValue;

    public int GetInt(string key, int defaultValue = 0) =>
        Params.TryGetValue(key, out var v) && int.TryParse(v?.ToString(), out var i) ? i : defaultValue;
}

public class RegisterRequest
{
    public string InstallSecret { get; set; } = "";
    public string Hostname { get; set; } = "";
    public string Fqdn { get; set; } = "";
    public string Group { get; set; } = "";
    public string AgentVersion { get; set; } = "";
}

public class RegisterResponse
{
    public string Token { get; set; } = "";
    public string ConfigUrl { get; set; } = "";
}

public class IngestRequest
{
    public string Module { get; set; } = "";
    public List<Dictionary<string, object?>> Records { get; set; } = new();
}

public class IngestResponse
{
    public int Inserted { get; set; }
    public int Skipped { get; set; }
}
