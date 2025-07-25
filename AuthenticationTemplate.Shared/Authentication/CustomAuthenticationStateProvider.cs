using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using AuthenticationTemplate.Shared.DTOs;
using AuthenticationTemplate.Shared.Interfaces;
using Microsoft.AspNetCore.Components;
using Microsoft.AspNetCore.Components.Authorization;

namespace AuthenticationTemplate.Shared.Authentication;

public class CustomAuthenticationStateProvider(
    ITokenStorage tokenStorage,
    HttpClient client,
    NavigationManager navigation)
    : AuthenticationStateProvider
{
    private readonly ClaimsPrincipal _anonymous = new(new ClaimsIdentity());
    private AuthenticationState? _cachedAuthState;

    public override async Task<AuthenticationState> GetAuthenticationStateAsync()
    {
        try
        {
            if (_cachedAuthState != null) return _cachedAuthState;
                
            var token = await tokenStorage.GetTokenAsync();
            
            if (string.IsNullOrEmpty(token) || IsExpired(token))
            {
                _cachedAuthState = new AuthenticationState(_anonymous);
                return _cachedAuthState;
            }

            var identity = ParseClaimsFromJwt(token);
            _cachedAuthState = new AuthenticationState(new ClaimsPrincipal(identity));
            return _cachedAuthState;
        }
        catch (InvalidOperationException ex) when (ex.Message.Contains("JavaScript interop"))
        {
            return new AuthenticationState(_anonymous);
        }
    }

    public async Task MarkUserAsAuthenticated(AuthResponse resp)
    {
        await tokenStorage.StoreTokensAsync(resp.AccessToken, resp.RefreshToken);
        _cachedAuthState = null;
        NotifyAuthenticationStateChanged(GetAuthenticationStateAsync());
    }

    public async Task MarkUserAsLoggedOut()
    {
        await tokenStorage.ClearTokensAsync();
        _cachedAuthState = null;
        NotifyAuthenticationStateChanged(GetAuthenticationStateAsync());
    }

    public async Task RefreshStateAsync()
    {
        var refresh = await tokenStorage.GetRefreshTokenAsync();
        
        if (string.IsNullOrEmpty(refresh))
        {
            await MarkUserAsLoggedOut();
            return;
        }

        var result = await AuthenticationClientService.RefreshToken(client, new RefreshTokenRequest(refresh));
        if (result.AuthResponse is null)
        {
            await MarkUserAsLoggedOut();
        }
        else
        {
            await MarkUserAsAuthenticated(result.AuthResponse);
            // navigation.NavigateTo(navigation.Uri, forceLoad: true);
        }
    }

    private static ClaimsIdentity ParseClaimsFromJwt(string jwt)
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
    
    private static bool IsExpired(string token)
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
