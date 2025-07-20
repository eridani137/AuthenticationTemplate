using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.DependencyInjection;
using OpenTelemetry.Exporter;
using OpenTelemetry.Metrics;
using OpenTelemetry.Resources;
using OpenTelemetry.Trace;

namespace AuthenticationTemplate.Core.Configuration;

public static class ConfigureOpenTelemetry
{
    public static void Configure(WebApplicationBuilder builder)
    {
        builder.Services.AddOpenTelemetry()
            .ConfigureResource(resource => resource
                .AddService(builder.Environment.ApplicationName))
            .WithTracing(tracing =>
            {
                tracing
                    .AddAspNetCoreInstrumentation(options =>
                    {
                        options.RecordException = true;
                        options.EnrichWithHttpRequest = (activity, request) =>
                        {
                            if (request.ContentLength.HasValue)
                            {
                                activity.SetTag("http.request.body.size", request.ContentLength);
                            }
                        };
                        options.EnrichWithHttpResponse = (activity, response) =>
                        {
                            if (response.ContentLength.HasValue)
                            {
                                activity.SetTag("http.response.body.size", response.ContentLength);
                            }
                        };
                    })
                    .AddHttpClientInstrumentation(options => options.RecordException = true)
                    .AddOtlpExporter();
            })
            .WithMetrics(metrics =>
            {
                metrics
                    .AddAspNetCoreInstrumentation()
                    .AddHttpClientInstrumentation()
                    .AddRuntimeInstrumentation()
                    .AddProcessInstrumentation()
                    .AddOtlpExporter();
            });
    }
}