using AuthenticationTemplate.AdminPanel.Components;
using AuthenticationTemplate.AdminPanel.Services;
using AuthenticationTemplate.ClientCore.Authentication;
using AuthenticationTemplate.ClientCore.Interfaces;
using AuthenticationTemplate.ClientCore.Services;
using AuthenticationTemplate.Core.Configuration;
using AuthenticationTemplate.Infrastructure;
using AuthenticationTemplate.Shared.Configs;
using Microsoft.AspNetCore.Components.Authorization;
using Microsoft.AspNetCore.HttpOverrides;
using Microsoft.Extensions.Options;
using MudBlazor;
using MudBlazor.Services;

var builder = WebApplication.CreateBuilder(args);

ConfigureLogging.Configure(builder);
ConfigureOpenTelemetry.Configure(builder);

builder.Services.Configure<ForwardedHeadersOptions>(options =>
{
    options.ForwardedHeaders = ForwardedHeaders.XForwardedFor |
                               ForwardedHeaders.XForwardedProto |
                               ForwardedHeaders.XForwardedHost;
    options.KnownNetworks.Clear();
    options.KnownProxies.Clear();
});

builder.Services.Configure<ApiConfig>(builder.Configuration.GetSection(nameof(ApiConfig)));

builder.Services.AddMongoDb(builder.Configuration);
builder.Services.AddIdentity(builder.Configuration);

builder.Services.AddRazorComponents()
    .AddInteractiveServerComponents();

builder.Services.AddMudServices(c =>
{
    c.SnackbarConfiguration.PositionClass = Defaults.Classes.Position.BottomCenter;
    c.SnackbarConfiguration.ShowCloseIcon = true;
    c.SnackbarConfiguration.VisibleStateDuration = 5000;
    c.SnackbarConfiguration.HideTransitionDuration = 500;
    c.SnackbarConfiguration.ShowTransitionDuration = 500;
    c.SnackbarConfiguration.SnackbarVariant = Variant.Filled;
});

builder.Services.AddSignalR(options =>
{
    options.ClientTimeoutInterval = TimeSpan.FromSeconds(60);
    options.KeepAliveInterval = TimeSpan.FromSeconds(15);
    options.HandshakeTimeout = TimeSpan.FromSeconds(30);
    options.MaximumReceiveMessageSize = 1024 * 1024;
    options.EnableDetailedErrors = builder.Environment.IsDevelopment();
});

builder.Services.AddAuthorization();
builder.Services.AddAuthenticationCore();

builder.Services.AddScoped<UserService>();

builder.Services.AddScoped<CustomAuthenticationMessageHandler>();

builder.Services.AddScoped<AuthenticationStateProvider, CustomAuthenticationStateProvider>();
builder.Services.AddScoped<CustomAuthenticationStateProvider>();

builder.Services.AddScoped<IApiClient, ApiClient>();

builder.Services.AddHttpClient<CustomAuthenticationStateProvider>((sp, client) =>
    {
        var config = sp.GetRequiredService<IOptions<ApiConfig>>().Value;

        client.BaseAddress = new Uri(config.BaseEndpoint);
        client.DefaultRequestHeaders.Add("Accept", "application/json");
    })
    .AddHttpMessageHandler<CustomAuthenticationMessageHandler>();

builder.Services.AddHttpClient<IApiClient, ApiClient>((sp, client) =>
{
    var config = sp.GetRequiredService<IOptions<ApiConfig>>().Value;

    client.BaseAddress = new Uri(config.BaseEndpoint);
    client.DefaultRequestHeaders.Add("Accept", "application/json");
});

ConfigureCors.Configure(builder);
ConfigureJwt.Configure(builder);

var app = builder.Build();

app.UseForwardedHeaders();

if (app.Environment.IsDevelopment())
{
    app.MapStaticAssets();
    app.UseDeveloperExceptionPage();
}
else
{
    app.UseExceptionHandler("/Error", createScopeForErrors: true);
    app.UseHsts();
    app.UseStaticFiles();
}

app.UseCors("AllowAll");

app.UseRouting();

app.UseAuthentication();
app.UseAuthorization();

app.UseAntiforgery();

app.MapRazorComponents<App>()
    .AddInteractiveServerRenderMode();

app.Run();