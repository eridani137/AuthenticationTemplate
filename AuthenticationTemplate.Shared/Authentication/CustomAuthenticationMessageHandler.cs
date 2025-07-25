using System.Net;
using System.Net.Http.Headers;
using AuthenticationTemplate.Shared.DTOs;
using Microsoft.AspNetCore.Components;
using Microsoft.AspNetCore.Components.Server.ProtectedBrowserStorage;
using Microsoft.JSInterop;

namespace AuthenticationTemplate.Shared.Authentication;

public class CustomAuthenticationMessageHandler(
    ProtectedLocalStorage storage,
    IJSRuntime jsRuntime,
    NavigationManager navigation)
    : DelegatingHandler
{
    private bool _isPrerendering = true;

    protected override async Task<HttpResponseMessage> SendAsync(
        HttpRequestMessage request,
        CancellationToken cancellationToken)
    {
        await AddAuthorizationHeaderAsync(request);

        var response = await base.SendAsync(request, cancellationToken);

        if (response.StatusCode == HttpStatusCode.Unauthorized)
        {
            await HandleUnauthorizedResponseAsync();
        }

        return response;
    }

    private async Task AddAuthorizationHeaderAsync(HttpRequestMessage request)
    {
        try
        {
            if (_isPrerendering)
            {
                try
                {
                    var result = await jsRuntime.InvokeAsync<bool>("window.hasOwnProperty", "localStorage");
                    _isPrerendering = false;
                }
                catch (InvalidOperationException)
                {
                    return;
                }
                catch (JSException)
                {
                    _isPrerendering = false;
                }
            }

            var authResponse = (await storage.GetAsync<AuthResponse>(CustomAuthenticationStateProvider.TokenKey)).Value;

            if (authResponse?.AccessToken != null && !CustomAuthenticationStateProvider.IsExpired(authResponse.AccessToken))
            {
                request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", authResponse.AccessToken);
            }
        }
        catch (InvalidOperationException)
        {
        }
        catch (Exception)
        {
            // ignored
        }
    }

    private async Task HandleUnauthorizedResponseAsync()
    {
        try
        {
            if (!_isPrerendering)
            {
                // Удаляем недействительный токен
                // await storage.DeleteAsync(CustomAuthenticationStateProvider.TokenKey);

                // Перенаправляем на страницу входа (опционально)
                // _navigation.NavigateTo("/login", forceLoad: true); // TODO
            }
        }
        catch (InvalidOperationException)
        {
        }
        catch (Exception)
        {
            // ignored
        }
    }
}