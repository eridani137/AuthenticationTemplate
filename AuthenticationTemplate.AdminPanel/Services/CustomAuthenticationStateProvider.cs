using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using Blazored.LocalStorage;
using Microsoft.AspNetCore.Components.Authorization;

namespace AuthenticationTemplate.AdminPanel.Services;

public class CustomAuthenticationStateProvider(IServiceProvider serviceProvider)
    : AuthenticationStateProvider
{
    private const string TokenKey = "access_token";
    private readonly ClaimsPrincipal _anonymous = new(new ClaimsIdentity());
    private bool _isInitialized;

    public override async Task<AuthenticationState> GetAuthenticationStateAsync()
    {
        if (!_isInitialized)
        {
            return new AuthenticationState(_anonymous);
        }

        using var scope = serviceProvider.CreateScope();
        var localStorage = scope.ServiceProvider.GetRequiredService<ILocalStorageService>();
        
        try
        {
            var token = await localStorage.GetItemAsync<string>(TokenKey);
            if (string.IsNullOrEmpty(token))
            {
                return new AuthenticationState(_anonymous);
            }

            var claimsPrincipal = new ClaimsPrincipal(new ClaimsIdentity(ParseClaimsFromJwt(token), "jwt"));
            return new AuthenticationState(claimsPrincipal);
        }
        catch
        {
            return new AuthenticationState(_anonymous);
        }
    }

    public Task InitializeAsync()
    {
        if (_isInitialized) return Task.CompletedTask;

        _isInitialized = true;
        NotifyAuthenticationStateChanged(GetAuthenticationStateAsync());
        return Task.CompletedTask;
    }

    public async Task MarkUserAsAuthenticated(string token)
    {
        using var scope = serviceProvider.CreateScope();
        var localStorage = scope.ServiceProvider.GetRequiredService<ILocalStorageService>();
        await localStorage.SetItemAsync(TokenKey, token);
        
        NotifyAuthenticationStateChanged(GetAuthenticationStateAsync());
    }

    public async Task MarkUserAsLoggedOut()
    {
        using var scope = serviceProvider.CreateScope();
        var localStorage = scope.ServiceProvider.GetRequiredService<ILocalStorageService>();
        await localStorage.RemoveItemAsync(TokenKey);

        NotifyAuthenticationStateChanged(GetAuthenticationStateAsync());
    }
    
    private static IEnumerable<Claim> ParseClaimsFromJwt(string jwt)
    {
        var handler = new JwtSecurityTokenHandler();
        var token = handler.ReadJwtToken(jwt);
        return token.Claims;
    }
}