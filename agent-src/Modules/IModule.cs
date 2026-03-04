namespace XiemAgent.Modules;

public interface IModule
{
    string Name { get; }
    Task<List<Dictionary<string, object?>>> CollectAsync(ModuleConfig config, CancellationToken ct);
}
