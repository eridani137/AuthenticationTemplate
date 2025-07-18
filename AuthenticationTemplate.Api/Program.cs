using AuthenticationTemplate.Shared.Configuration;
using Carter;

var builder = WebApplication.CreateBuilder(args);

ConfigureLogging.Configure(builder);

builder.Services.AddOpenApi();
builder.Services.AddCarter();
builder.Services.AddEndpointsApiExplorer();

ConfigureCors.Configure(builder);

var app = builder.Build();

if (app.Environment.IsDevelopment())
{
    app.MapOpenApi();
}

app.UseCors("AllowAll");
app.MapCarter();
// app.UseHttpsRedirection();

app.Run();