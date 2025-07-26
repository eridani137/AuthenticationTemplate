using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using AuthenticationTemplate.Shared.DTOs;
using AuthenticationTemplate.Shared.Services;
using Microsoft.AspNetCore.Components;
using Microsoft.AspNetCore.Components.Authorization;
using Microsoft.AspNetCore.Components.Server.ProtectedBrowserStorage;
using Microsoft.JSInterop;

namespace AuthenticationTemplate.Shared.Authentication;

public class CustomAuthenticationStateProvider(
    HttpClient client,
    NavigationManager navigation,
    ProtectedLocalStorage storage,
    IJSRuntime jsRuntime)
    : AuthenticationStateProvider
{
    private readonly ClaimsPrincipal _anonymous = new(new ClaimsIdentity());
    private AuthenticationState? _cachedAuthState;
    private bool _isPrerendering = true;
    
    public const string TokenKey = "tokens";

    public override async Task<AuthenticationState> GetAuthenticationStateAsync()
    {
        try
        {
            if (_cachedAuthState != null) return _cachedAuthState;

            if (_isPrerendering)
            {
                try
                {
                    await jsRuntime.InvokeAsync<bool>("window.hasOwnProperty", "localStorage");
                    _isPrerendering = false;
                }
                catch (InvalidOperationException)
                {
                    _cachedAuthState = new AuthenticationState(_anonymous);
                    return _cachedAuthState;
                }
                catch (JSException)
                {
                    _isPrerendering = false;
                }
            }

            var authResponse = (await storage.GetAsync<AuthResponse>(TokenKey)).Value;

            if (authResponse is null || IsExpired(authResponse.AccessToken))
            {
                _cachedAuthState = new AuthenticationState(_anonymous);
                return _cachedAuthState;
            }

            var identity = ParseClaimsFromJwt(authResponse.AccessToken);
            _cachedAuthState = new AuthenticationState(new ClaimsPrincipal(identity));
            return _cachedAuthState;
        }
        catch (InvalidOperationException)
        {
            return new AuthenticationState(_anonymous);
        }
        catch
        {
            return new AuthenticationState(_anonymous);
        }
    }

    public async Task MarkUserAsAuthenticated(AuthResponse response)
    {
        try
        {
            await storage.SetAsync(TokenKey, response);
            _cachedAuthState = null;
            _isPrerendering = false;
            NotifyAuthenticationStateChanged(GetAuthenticationStateAsync());
        }
        catch
        {
            // ignored
        }
    }

    public async Task MarkUserAsLoggedOut()
    {
        try
        {
            await storage.DeleteAsync(TokenKey);
            _cachedAuthState = new AuthenticationState(_anonymous);
            _isPrerendering = false;
            NotifyAuthenticationStateChanged(GetAuthenticationStateAsync());
        }
        catch
        {
            _cachedAuthState = new AuthenticationState(_anonymous);
            NotifyAuthenticationStateChanged(Task.FromResult(_cachedAuthState));
        }
    }

    public async Task RefreshStateAsync()
    {
        _isPrerendering = false;
        _cachedAuthState = null;

        var authResponse = (await storage.GetAsync<AuthResponse>(TokenKey)).Value;

        if (authResponse is not null)
        {
            if (IsExpired(authResponse.AccessToken))
            {
                if (string.IsNullOrEmpty(authResponse.RefreshToken))
                {
                    await MarkUserAsLoggedOut();
                    navigation.NavigateTo("/login", forceLoad: true);
                }
                else
                {
                    var result = await ApiClient.RefreshToken(client, new RefreshTokenRequest(authResponse.RefreshToken));
                    if (result.AuthResponse is not null)
                    {
                        await MarkUserAsAuthenticated(result.AuthResponse);
                        navigation.NavigateTo(navigation.Uri, forceLoad: true);
                    }
                    else
                    {
                        await MarkUserAsLoggedOut();
                    }
                }
            }
        }
    }

    public static ClaimsIdentity ParseClaimsFromJwt(string jwt)
    {
        var handler = new JwtSecurityTokenHandler();
        var token = handler.ReadJwtToken(jwt);

        return new ClaimsIdentity(
            token.Claims,
            authenticationType: "jwt",
            nameType: JwtRegisteredClaimNames.Nickname,
            roleType: "role"
        );
    }

    public static bool IsExpired(string token)
    {
        try
        {
            var handler = new JwtSecurityTokenHandler();
            var jwtToken = handler.ReadJwtToken(token);

            var expClaim = jwtToken.Claims.FirstOrDefault(c => c.Type == "exp")?.Value;
            if (string.IsNullOrWhiteSpace(expClaim) || !long.TryParse(expClaim, out var exp))
                return true;

            var expiry = DateTimeOffset.FromUnixTimeSeconds(exp);
            return expiry <= DateTimeOffset.UtcNow;
        }
        catch
        {
            return true;
        }
    }
}