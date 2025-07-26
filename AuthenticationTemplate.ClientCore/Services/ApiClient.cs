using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using AuthenticationTemplate.ClientCore.Authentication;
using AuthenticationTemplate.ClientCore.Extensions;
using AuthenticationTemplate.ClientCore.Interfaces;
using AuthenticationTemplate.Shared.DTOs;
using Microsoft.AspNetCore.Components.Server.ProtectedBrowserStorage;
using Microsoft.AspNetCore.Mvc;
using Microsoft.JSInterop;
using LoginRequest = AuthenticationTemplate.Shared.DTOs.LoginRequest;

namespace AuthenticationTemplate.ClientCore.Services;

public class ApiClient(HttpClient client, ProtectedLocalStorage storage, IJSRuntime jsRuntime) : IApiClient
{
    private bool _isPrerendering = true;
    private const string AuthEndpoint = "/auth";

    public async Task<ClientAuthResponse> Login(LoginRequest request)
    {
        var response = await client.PostAsJsonAsync($"{AuthEndpoint}/login", request);

        ProblemDetails? problemDetails = null;
        if (response.StatusCode == HttpStatusCode.Unauthorized)
        {
            var (requiredTwoFactorCode, problem) = await response.HasRequiredTwoFactorCode();
            if (requiredTwoFactorCode is not null)
            {
                return requiredTwoFactorCode;
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
        var response = await client.PostAsJsonAsync($"{AuthEndpoint}/refresh-token", request);
        
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
        
        var response = await client.PostAsJsonAsync($"{AuthEndpoint}/change-password", request);
        
        if (!response.IsSuccessStatusCode)
        {
            var message = (await response.GetProblemDetails())?.Detail;
            return new ServerResponse(response.StatusCode, message);
        }

        return new ServerResponse(response.StatusCode, null);
    }

    public async Task<TwoFactorStatusResponse?> GetTwoFactorStatus()
    {
        await AddAuthorizationHeaderAsync();
        
        var response = await client.GetAsync($"{AuthEndpoint}/2fa");

        if (!response.IsSuccessStatusCode)
        {
            return null;
        }
        
        return await response.Content.ReadFromJsonAsync<TwoFactorStatusResponse>();
    }

    public async Task<ClientSetupTwoFactorRequest> GetTwoFactorSetup()
    {
        await AddAuthorizationHeaderAsync();
        
        var response = await client.GetAsync($"{AuthEndpoint}/2fa/setup");

        if (!response.IsSuccessStatusCode)
        {
            var message = (await response.GetProblemDetails())?.Detail;
            return new ClientSetupTwoFactorRequest(null, new ServerResponse(response.StatusCode, message));
        }
        
        var setupResponse = await response.Content.ReadFromJsonAsync<SetupTwoFactorRequest>();

        return new ClientSetupTwoFactorRequest(setupResponse, new ServerResponse(response.StatusCode, null));
    }

    public async Task<ClientRecoveryCodesResponse> EnableTwoFactor(TwoFactorCodeRequest request)
    {
        await AddAuthorizationHeaderAsync();

        var response = await client.PostAsJsonAsync($"{AuthEndpoint}/2fa/enable", request);

        if (!response.IsSuccessStatusCode)
        {
            var message = (await response.GetProblemDetails())?.Detail;
            return new ClientRecoveryCodesResponse(null, new ServerResponse(response.StatusCode, message));
        }

        var codesResponse = await response.Content.ReadFromJsonAsync<RecoveryCodesResponse>();

        return new ClientRecoveryCodesResponse(codesResponse, new ServerResponse(response.StatusCode, null));
    }
    
    public async Task<ServerResponse> DisableTwoFactorAsync(TwoFactorCodeRequest request)
    {
        await AddAuthorizationHeaderAsync();

        var response = await client.PostAsJsonAsync($"{AuthEndpoint}/2fa/disable", request);

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