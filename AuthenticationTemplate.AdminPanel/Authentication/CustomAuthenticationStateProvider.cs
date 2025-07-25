using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using AuthenticationTemplate.AdminPanel.Services;
using AuthenticationTemplate.Shared.DTOs;
using Blazored.LocalStorage;
using Microsoft.AspNetCore.Components.Authorization;
using Microsoft.JSInterop;

namespace AuthenticationTemplate.AdminPanel.Authentication;

public class CustomAuthenticationStateProvider(
    ILocalStorageService localStorage,
    HttpClient client,
    IJSRuntime jsRuntime) : AuthenticationStateProvider
{
    private const string TokenKey = "access_token";
    private const string RefreshKey = "refresh_token";
    private readonly ClaimsPrincipal _anonymous = new(new ClaimsIdentity());

    public string? Token { get; private set; }
    public string? RefreshToken { get; private set; }

    private bool IsJavaScriptAvailable()
    {
        try
        {
            return jsRuntime is not IJSInProcessRuntime &&
                   jsRuntime.GetType().Name != "UnsupportedJavaScriptRuntime";
        }
        catch
        {
            return false;
        }
    }

    private async Task<string> GetTokenFromLocalStorageAsync()
    {
        if (!IsJavaScriptAvailable())
        {
            return string.Empty;
        }

        try
        {
            return await localStorage.GetItemAsync<string>(TokenKey) ?? string.Empty;
        }
        catch (InvalidOperationException)
        {
            return string.Empty;
        }
        catch (JSException)
        {
            return string.Empty;
        }
    }

    public override async Task<AuthenticationState> GetAuthenticationStateAsync()
    {
        if (!IsJavaScriptAvailable())
        {
            return new AuthenticationState(_anonymous);
        }

        if (string.IsNullOrEmpty(Token))
        {
            Token = await GetTokenFromLocalStorageAsync();
        }

        if (string.IsNullOrEmpty(Token) || IsTokenExpired(Token))
        {
            return new AuthenticationState(_anonymous);
        }

        var identity = ParseClaimsFromJwt(Token);
        return new AuthenticationState(new ClaimsPrincipal(identity));
    }

    public async Task MarkUserAsAuthenticated(AuthResponse response)
    {
        Token = response.AccessToken;
        RefreshToken = response.RefreshToken;

        if (IsJavaScriptAvailable())
        {
            try
            {
                await localStorage.SetItemAsync(TokenKey, response.AccessToken);
                await localStorage.SetItemAsync(RefreshKey, response.RefreshToken);
            }
            catch
            {
                // ignored
            }
        }

        NotifyAuthenticationStateChanged(GetAuthenticationStateAsync());
    }

    public async Task MarkUserAsLoggedOut()
    {
        Token = null;
        RefreshToken = null;

        if (IsJavaScriptAvailable())
        {
            try
            {
                await localStorage.RemoveItemAsync(TokenKey);
                await localStorage.RemoveItemAsync(RefreshKey);
            }
            catch
            {
                // ignored
            }
        }

        NotifyAuthenticationStateChanged(GetAuthenticationStateAsync());
    }

    public async Task RefreshStateAsync()
    {
        if (!IsJavaScriptAvailable()) return;

        Token ??= await GetTokenFromLocalStorageAsync();

        if (string.IsNullOrEmpty(Token))
        {
            NotifyAuthenticationStateChanged(Task.FromResult(new AuthenticationState(_anonymous)));
            return;
        }

        RefreshToken ??= await localStorage.GetItemAsync<string>(RefreshKey);

        if (!IsTokenExpired(Token))
        {
            NotifyAuthenticationStateChanged(GetAuthenticationStateAsync());
            return;
        }

        if (string.IsNullOrEmpty(RefreshToken))
        {
            await MarkUserAsLoggedOut();
            return;
        }

        try
        {
            var result = await AuthService.RefreshToken(client, new RefreshTokenRequest(RefreshToken));

            if (result is not null)
            {
                await MarkUserAsAuthenticated(result);
            }
            else
            {
                await MarkUserAsLoggedOut();
            }
        }
        catch
        {
            await MarkUserAsLoggedOut();
        }
    }

    private static ClaimsIdentity ParseClaimsFromJwt(string jwt)
    {
        var handler = new JwtSecurityTokenHandler();
        var token = handler.ReadJwtToken(jwt);
        var claims = token.Claims;
        return new ClaimsIdentity(claims, "jwt");
    }

    private static bool IsTokenExpired(string token)
    {
        try
        {
            var claimsIdentity = ParseClaimsFromJwt(token);
            var expiry = claimsIdentity.Claims.FirstOrDefault(c => c.Type.Equals("exp"))?.Value;
            if (string.IsNullOrEmpty(expiry) || !long.TryParse(expiry, out var expiryTimeStamp)) return true;
            var expiryDateTimeOffset = DateTimeOffset.FromUnixTimeSeconds(expiryTimeStamp);
            return expiryDateTimeOffset <= DateTimeOffset.UtcNow;
        }
        catch
        {
            return true;
        }
    }
}