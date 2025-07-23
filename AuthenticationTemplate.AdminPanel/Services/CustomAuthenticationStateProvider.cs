using System.Security.Claims;
using System.Text.Json;
using Blazored.LocalStorage;
using Microsoft.AspNetCore.Components.Authorization;
using Microsoft.JSInterop;

namespace AuthenticationTemplate.AdminPanel.Services;

public class CustomAuthenticationStateProvider(ILocalStorageService localStorage)
    : AuthenticationStateProvider
{
    private readonly ClaimsPrincipal _anonymous = new(new ClaimsIdentity());
    private ClaimsPrincipal? _user;
    private bool _initialized;

    public override Task<AuthenticationState> GetAuthenticationStateAsync()
    {
        return Task.FromResult(!_initialized ? new AuthenticationState(_anonymous) : new AuthenticationState(_user));
    }

    public async Task InitializeAsync()
    {
        var token = await localStorage.GetItemAsync<string>("access_token");
        if (string.IsNullOrWhiteSpace(token))
        {
            _user = _anonymous;
        }
        else
        {
            var identity = new ClaimsIdentity(ParseClaimsFromJwt(token), "jwt");
            _user = new ClaimsPrincipal(identity);
        }

        _initialized = true;
        NotifyAuthenticationStateChanged(Task.FromResult(new AuthenticationState(_user)));
    }

    private IEnumerable<Claim> ParseClaimsFromJwt(string jwt)
    {
        var claims = new List<Claim>();
        var payload = jwt.Split('.')[1];
        var jsonBytes = ParseBase64WithoutPadding(payload);
        var keyValuePairs = JsonSerializer.Deserialize<Dictionary<string, object>>(jsonBytes);

        foreach (var kvp in keyValuePairs)
        {
            claims.Add(new Claim(kvp.Key, kvp.Value.ToString()));
        }

        return claims;
    }

    private byte[] ParseBase64WithoutPadding(string base64)
    {
        base64 = base64.Replace('-', '+').Replace('_', '/');
        switch (base64.Length % 4)
        {
            case 2: base64 += "=="; break;
            case 3: base64 += "="; break;
        }
        return Convert.FromBase64String(base64);
    }
}