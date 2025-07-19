using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.DependencyInjection;

namespace AuthenticationTemplate.Core.Configuration;

public static class ConfigureCors
{
    public static void Configure(WebApplicationBuilder builder)
    {
        builder.Services.AddCors(options =>
        {
            options.AddPolicy("AllowAll", policy =>
            {
                policy
                    .AllowAnyOrigin()
                    .AllowAnyMethod()
                    .AllowAnyHeader();
            });
        });
    }
}