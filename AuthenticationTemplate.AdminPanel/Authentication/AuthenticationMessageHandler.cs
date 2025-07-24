using System.Net;
using System.Net.Http.Headers;
using Microsoft.AspNetCore.Components;
using Microsoft.JSInterop;

namespace AuthenticationTemplate.AdminPanel.Authentication;

public class AuthenticationMessageHandler(
    CustomAuthenticationStateProvider authStateProvider,
    NavigationManager navigation,
    IJSRuntime? jsRuntime,
    ILogger<AuthenticationMessageHandler> logger)
    : DelegatingHandler
{
    protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request,
        CancellationToken cancellationToken)
    {
        var isInteractive = IsInteractiveMode();

        if (!string.IsNullOrEmpty(authStateProvider.Token))
        {
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", authStateProvider.Token);
        }

        var response = await base.SendAsync(request, cancellationToken);

        if (response.StatusCode == HttpStatusCode.Unauthorized && isInteractive)
        {
            await HandleUnauthorizedResponse();
        }

        return response;
    }
    
    private bool IsInteractiveMode()
    {
        try
        {
            var uri = navigation.Uri;
            
            return jsRuntime is not null && jsRuntime.GetType().Name != "UnsupportedJavaScriptRuntime";
        }
        catch (InvalidOperationException)
        {
            return false;
        }
    }
    
    private async Task HandleUnauthorizedResponse()
    {
        try
        {
            await authStateProvider.MarkUserAsLoggedOut();
            
            var currentUri = navigation.Uri;
            const string loginPath = "/login";
            
            if (!currentUri.Contains(loginPath, StringComparison.OrdinalIgnoreCase))
            {
                navigation.NavigateTo(loginPath, forceLoad: true);
            }
        }
        catch (InvalidOperationException)
        {
        }
        catch (Exception e)
        {
            logger.LogError(e, e.Message);
        }
    }
}