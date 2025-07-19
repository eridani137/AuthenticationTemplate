using AuthenticationTemplate.Core.Configuration;
using Carter;
using Scalar.AspNetCore;

var builder = WebApplication.CreateBuilder(args);

ConfigureLogging.Configure(builder);

builder.Services.AddOpenApi();
builder.Services.AddCarter();
builder.Services.AddEndpointsApiExplorer();

ConfigureCors.Configure(builder);

var app = builder.Build();

app.MapOpenApi();
app.MapScalarApiReference();

app.UseCors("AllowAll");
app.MapCarter();


app.Run();