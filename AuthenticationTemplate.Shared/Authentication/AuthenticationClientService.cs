using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using AuthenticationTemplate.Shared.DTOs;
using AuthenticationTemplate.Shared.Extensions;
using Microsoft.AspNetCore.Components.Server.ProtectedBrowserStorage;
using Microsoft.AspNetCore.Mvc;
using Microsoft.JSInterop;

namespace AuthenticationTemplate.Shared.Authentication;

public class AuthenticationClientService(HttpClient client, ProtectedLocalStorage storage, IJSRuntime jsRuntime)
{
    private bool _isPrerendering = true;
    private const string Endpoint = "/auth";

    public async Task<ClientAuthResponse> Login(LoginRequest request)
    {
        var response = await client.PostAsJsonAsync($"{Endpoint}/login", request);

        ProblemDetails? problemDetails = null;
        if (response.StatusCode == HttpStatusCode.Unauthorized)
        {
            var (required2FaCode, problem) = await response.HasRequired2FaCode();
            if (required2FaCode is not null)
            {
                return required2FaCode;
            }
            problemDetails = problem;
        }

        if (response is { IsSuccessStatusCode: false, StatusCode: HttpStatusCode.Unauthorized })
        {
            var message = problemDetails?.Detail;
            return new ClientAuthResponse(null, false, new ServerResponse(response.StatusCode, message));
        }
        
        var authResponse = await response.Content.ReadFromJsonAsync<AuthResponse>();
        return new ClientAuthResponse(authResponse, false, new ServerResponse(response.StatusCode, null));
    }

    public static async Task<ClientAuthResponse> RefreshToken(HttpClient client, RefreshTokenRequest request)
    {
        var response = await client.PostAsJsonAsync($"{Endpoint}/refresh-token", request);
        
        if (!response.IsSuccessStatusCode)
        {
            var message = (await response.GetProblemDetails())?.Detail;
            return new ClientAuthResponse(null, false, new ServerResponse(response.StatusCode, message));
        }

        var authResponse = await response.Content.ReadFromJsonAsync<AuthResponse>();
        
        return new ClientAuthResponse(authResponse, false, new ServerResponse(response.StatusCode, null));
    }

    public async Task<ServerResponse> ChangePassword(ChangePasswordRequest request)
    {
        await AddAuthorizationHeaderAsync();
        
        var response = await client.PostAsJsonAsync($"{Endpoint}/change-password", request);
        
        if (!response.IsSuccessStatusCode)
        {
            var message = (await response.GetProblemDetails())?.Detail;
            return new ServerResponse(response.StatusCode, message);
        }

        return new ServerResponse(response.StatusCode, null);
    }
    
    private async Task AddAuthorizationHeaderAsync()
    {
        try
        {
            if (_isPrerendering)
            {
                try
                {
                    await jsRuntime.InvokeAsync<bool>("window.hasOwnProperty", "localStorage");
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
                client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", authResponse.AccessToken);
            }
            else
            {
                client.DefaultRequestHeaders.Authorization = null;
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