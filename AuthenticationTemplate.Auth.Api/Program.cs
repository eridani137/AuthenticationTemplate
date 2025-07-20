using AuthenticationTemplate.Core.Configuration;
using AuthenticationTemplate.Core.Extensions;
using AuthenticationTemplate.Infrastructure;
using Carter;
using Scalar.AspNetCore;
using Serilog;

var builder = WebApplication.CreateBuilder(args);

ConfigureLogging.Configure(builder);
ConfigureOpenTelemetry.Configure(builder);

builder.Services.AddOpenApi();
builder.Services.AddCarter();
builder.Services.AddEndpointsApiExplorer();

builder.Services.AddApplication();
builder.Services.AddInfrastructure(builder.Configuration);

ConfigureCors.Configure(builder);
ConfigureJwt.Configure(builder);

var app = builder.Build();

app.UseSerilogRequestLogging();

app.MapOpenApi();
app.MapScalarApiReference();

app.UseCors("AllowAll");

app.UseAuthentication();
app.UseAuthorization();

app.MapCarter();

await InitApp.Init(app);

app.Run();