using XiemAgent.Modules;

namespace XiemAgent;

public class Worker : BackgroundService
{
    private readonly ILogger<Worker> _log;
    private readonly ApiClient _api;
    private readonly IEnumerable<IModule> _modules;
    private readonly IConfiguration _config;

    public Worker(ILogger<Worker> log, ApiClient api, IEnumerable<IModule> modules, IConfiguration config)
    {
        _log = log;
        _api = api;
        _modules = modules;
        _config = config;
    }

    protected override async Task ExecuteAsync(CancellationToken ct)
    {
        _log.LogInformation("XiemAgent starting");

        if (string.IsNullOrEmpty(_config["Xiem:Token"]))
        {
            _log.LogCritical("No token in config. Run install script first.");
            return;
        }

        var agentConfig = await _api.GetConfigAsync(ct);
        if (agentConfig == null)
        {
            _log.LogCritical("Failed to fetch config from server");
            return;
        }

        _log.LogInformation("Config loaded, {Count} modules", agentConfig.Modules.Count);

        var tasks = new List<Task>();
        foreach (var moduleCfg in agentConfig.Modules.Where(m => m.Enabled))
        {
            var module = _modules.FirstOrDefault(m => m.Name == moduleCfg.Name);
            if (module == null)
            {
                _log.LogWarning("Module {Name} not found", moduleCfg.Name);
                continue;
            }
            tasks.Add(RunModuleLoopAsync(module, moduleCfg, ct));
        }

        tasks.Add(HeartbeatLoopAsync(ct));
        await Task.WhenAll(tasks);
    }

    private async Task RunModuleLoopAsync(IModule module, ModuleConfig config, CancellationToken ct)
    {
        var interval = TimeSpan.FromSeconds(config.IntervalSec);
        _log.LogInformation("Module {Name} starting, interval={Interval}s", module.Name, config.IntervalSec);

        while (!ct.IsCancellationRequested)
        {
            try
            {
                var records = await module.CollectAsync(config, ct);
                if (records.Count > 0)
                {
                    var result = await _api.IngestAsync(new IngestRequest
                    {
                        Module  = module.Name,
                        Records = records
                    }, ct);

                    if (result != null)
                        _log.LogInformation("Module {Name}: inserted={Inserted} skipped={Skipped}",
                            module.Name, result.Inserted, result.Skipped);
                }
            }
            catch (OperationCanceledException) { break; }
            catch (Exception ex)
            {
                _log.LogError(ex, "Module {Name} failed, will retry next interval", module.Name);
            }

            try { await Task.Delay(interval, ct); }
            catch (OperationCanceledException) { break; }
        }

        _log.LogInformation("Module {Name} stopped", module.Name);
    }

    private async Task HeartbeatLoopAsync(CancellationToken ct)
    {
        while (!ct.IsCancellationRequested)
        {
            try { await Task.Delay(TimeSpan.FromMinutes(5), ct); }
            catch (OperationCanceledException) { break; }
            await _api.HeartbeatAsync(ct);
        }
    }
}
