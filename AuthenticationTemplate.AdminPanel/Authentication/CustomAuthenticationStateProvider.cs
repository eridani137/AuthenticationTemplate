using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using AuthenticationTemplate.Shared.DTOs;
using Blazored.LocalStorage;
using Microsoft.AspNetCore.Components.Authorization;
using Microsoft.JSInterop;

namespace AuthenticationTemplate.AdminPanel.Authentication;

public class CustomAuthenticationStateProvider(ILocalStorageService localStorage, IJSRuntime jsRuntime) : AuthenticationStateProvider
{
    private const string TokenKey = "access_token";
    private const string RefreshKey = "refresh_token";
    private readonly ClaimsPrincipal _anonymous = new(new ClaimsIdentity());

    public string? Token { get; private set; }
    public string? RefreshToken { get; private set; }

    // Проверяем, доступен ли JavaScript interop
    private bool IsJavaScriptAvailable()
    {
        try
        {
            // Простая проверка на доступность JS
            return jsRuntime is not IJSInProcessRuntime && 
                   jsRuntime.GetType().Name != "UnsupportedJavaScriptRuntime";
        }
        catch
        {
            return false;
        }
    }

    public async Task<string> GetTokenFromLocalStorageAsync()
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
        // Во время prerendering всегда возвращаем анонимного пользователя
        if (!IsJavaScriptAvailable())
        {
            return new AuthenticationState(_anonymous);
        }

        // Если токен еще не загружен, пытаемся загрузить из localStorage
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
            catch (InvalidOperationException)
            {
                // JavaScript недоступен, токены остаются только в памяти
            }
            catch (JSException)
            {
                // Ошибка JavaScript, токены остаются только в памяти
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
            catch (InvalidOperationException)
            {
                // JavaScript недоступен
            }
            catch (JSException)
            {
                // Ошибка JavaScript
            }
        }
        
        NotifyAuthenticationStateChanged(GetAuthenticationStateAsync());
    }

    // Вызывать этот метод после завершения prerendering
    public async Task RefreshStateAsync()
    {
        if (IsJavaScriptAvailable() && string.IsNullOrEmpty(Token))
        {
            Token = await GetTokenFromLocalStorageAsync();
            if (!string.IsNullOrEmpty(Token))
            {
                try
                {
                    RefreshToken = await localStorage.GetItemAsync<string>(RefreshKey);
                }
                catch
                {
                    // Игнорируем ошибки при загрузке refresh token
                }
                NotifyAuthenticationStateChanged(GetAuthenticationStateAsync());
            }
        }
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