using AuthenticationTemplate.AdminPanel.Components;
using AuthenticationTemplate.Core.Configuration;
using Blazored.LocalStorage;
using MudBlazor;
using MudBlazor.Services;

var builder = WebApplication.CreateBuilder(args);

ConfigureLogging.Configure(builder);
ConfigureOpenTelemetry.Configure(builder);

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
builder.Services.AddBlazoredLocalStorage();

ConfigureCors.Configure(builder);
ConfigureJwt.Configure(builder);
builder.Services.AddAuthorizationCore();

var app = builder.Build();

if (!app.Environment.IsDevelopment())
{
    app.UseExceptionHandler("/Error", createScopeForErrors: true);
    app.UseHsts();
}

app.UseHttpsRedirection();


app.UseAntiforgery();

app.MapRazorComponents<App>()
    .AddInteractiveServerRenderMode();

app.Run();