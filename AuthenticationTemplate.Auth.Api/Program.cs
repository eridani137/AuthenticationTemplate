using AuthenticationTemplate.Application;
using AuthenticationTemplate.Core.Configuration;
using AuthenticationTemplate.Infrastructure;
using Carter;
using Scalar.AspNetCore;

var builder = WebApplication.CreateBuilder(args);

ConfigureLogging.Configure(builder);

builder.Services.AddOpenApi();
builder.Services.AddCarter();
builder.Services.AddEndpointsApiExplorer();

builder.Services.AddApplication();
builder.Services.AddInfrastructure(builder.Configuration);

ConfigureCors.Configure(builder);

var app = builder.Build();

// if (app.Environment.IsDevelopment())
{
    app.MapOpenApi();
    app.MapScalarApiReference();
}

app.UseCors("AllowAll");
app.MapCarter();
// app.UseHttpsRedirection();

app.Run();