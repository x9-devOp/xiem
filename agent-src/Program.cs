using Microsoft.Extensions.Hosting.WindowsServices;
using XiemAgent;
using XiemAgent.Modules;

var builder = Host.CreateApplicationBuilder(args);

builder.Services.AddWindowsService(options =>
{
    options.ServiceName = "XiemAgent";
});

builder.Services.AddHttpClient<ApiClient>(client =>
{
    var baseUrl = builder.Configuration["Xiem:BaseUrl"]
        ?? throw new InvalidOperationException("Xiem:BaseUrl not configured");
    client.BaseAddress = new Uri(baseUrl);
    client.Timeout = TimeSpan.FromSeconds(30);
});

builder.Services.AddSingleton<IModule, EsetNetworkModule>();
builder.Services.AddSingleton<IModule, AuthFailuresModule>();
builder.Services.AddSingleton<XiemAgent.Modules.ScriptModule>();
builder.Services.AddSingleton<CommandPoller>();
builder.Services.AddHostedService<Worker>();

var host = builder.Build();
host.Run();
