using Microsoft.AspNetCore.Builder;
using Serilog;
using Serilog.Core;
using Serilog.Events;
using Serilog.Exceptions;

namespace AuthenticationTemplate.Core.Configuration;

public static class ConfigureLogging
{
    public static void Configure(WebApplicationBuilder builder)
    {
        const string logs = "logs";
        var logsPath = Path.GetFullPath(Path.Combine(AppDomain.CurrentDomain.BaseDirectory, logs));

        if (!Directory.Exists(logsPath))
        {
            Directory.CreateDirectory(logsPath);
        }

        const string outputTemplate =
            "[{Timestamp:HH:mm:ss} {Level:u3}] [{SourceContext}] {Message:lj}{NewLine}{Exception}";

        var endpoint = Environment.GetEnvironmentVariable("OTEL_EXPORTER_OTLP_ENDPOINT")!;
        var serviceName = Environment.GetEnvironmentVariable("OTEL_SERVICE_NAME")!;
        var levelSwitch = new LoggingLevelSwitch();

        var configuration = new LoggerConfiguration()
            .MinimumLevel.ControlledBy(levelSwitch)
            .MinimumLevel.Override("Microsoft.AspNetCore", LogEventLevel.Warning)
            .MinimumLevel.Override("System.Net.Http.HttpClient", LogEventLevel.Warning)
            .MinimumLevel.Override("Polly", LogEventLevel.Warning)
            .Enrich.FromLogContext()
            .Enrich.WithMachineName()
            .Enrich.WithEnvironmentName()
            .Enrich.WithExceptionDetails()
            .Enrich.WithProperty("ServiceName", serviceName)
            .WriteTo.Console(outputTemplate: outputTemplate, levelSwitch: levelSwitch);
            // .WriteTo.File($"{logsPath}/.log", rollingInterval: RollingInterval.Day, outputTemplate: outputTemplate, levelSwitch: levelSwitch);

        if (!string.IsNullOrWhiteSpace(endpoint) && !string.IsNullOrWhiteSpace(serviceName))
        {
            configuration.WriteTo.Seq(endpoint, controlLevelSwitch: levelSwitch);
        }
        
        Log.Logger = configuration.CreateLogger();
        
        builder.Host.UseSerilog(Log.Logger);
    }
}