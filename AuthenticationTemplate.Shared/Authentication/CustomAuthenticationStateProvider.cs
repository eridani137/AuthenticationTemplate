using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using AuthenticationTemplate.Shared.DTOs;
using Blazored.LocalStorage;
using Microsoft.AspNetCore.Components.Authorization;

namespace AuthenticationTemplate.Shared.Authentication;

public class CustomAuthenticationStateProvider(ILocalStorageService localStorage) : AuthenticationStateProvider
{
    private const string TokenKey = "access_token";
    private const string RefreshKey = "refresh_token";
    private readonly ClaimsPrincipal _anonymous = new(new ClaimsIdentity());
    private bool _isInitialized;

    public string? Token;
    public string? RefreshToken;

    public async Task<string> GetTokenFromLocalStorage()
    {
        return await localStorage.GetItemAsync<string>(TokenKey) ?? string.Empty;
    }
    
    public override Task<AuthenticationState> GetAuthenticationStateAsync()
    {
        if (!_isInitialized || string.IsNullOrEmpty(Token) || IsTokenExpired(Token))
        {
            return Task.FromResult(new AuthenticationState(_anonymous));
        }

        var identity = ParseClaimsFromJwt(Token);
        return Task.FromResult(new AuthenticationState(new ClaimsPrincipal(identity)));
        
        // try
        // {
        //     // var token = await GetTokenFromLocalStorage();
        //     // if (string.IsNullOrEmpty(token))
        //     // {
        //     //     return new AuthenticationState(_anonymous);
        //     // }
        //
        //     var claimsPrincipal = new ClaimsPrincipal(ParseClaimsFromJwt(token));
        //     return new AuthenticationState(claimsPrincipal);
        // }
        // catch
        // {
        //     return new AuthenticationState(_anonymous);
        // }
    }

    public Task InitializeAsync()
    {
        if (_isInitialized) return Task.CompletedTask;

        _isInitialized = true;
        NotifyAuthenticationStateChanged(GetAuthenticationStateAsync());
        
        return Task.CompletedTask;
    }

    public async Task MarkUserAsAuthenticated(AuthResponse response)
    {
        Token = response.AccessToken;
        RefreshToken = response.RefreshToken;
        await localStorage.SetItemAsync(TokenKey, response.AccessToken);
        await localStorage.SetItemAsync(RefreshKey, response.RefreshToken);
        NotifyAuthenticationStateChanged(GetAuthenticationStateAsync());
    }

    public async Task MarkUserAsLoggedOut()
    {
        Token = null;
        RefreshToken = null;
        await localStorage.RemoveItemAsync(TokenKey);
        await localStorage.RemoveItemAsync(RefreshKey);
        NotifyAuthenticationStateChanged(GetAuthenticationStateAsync());
    }

    private static ClaimsIdentity ParseClaimsFromJwt(string jwt)
    {
        var handler = new JwtSecurityTokenHandler();
        var token = handler.ReadJwtToken(jwt);
        var claims = token.Claims;
        return new ClaimsIdentity(claims, "jwt");
    }
    
    public static bool IsTokenExpired(string token)
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