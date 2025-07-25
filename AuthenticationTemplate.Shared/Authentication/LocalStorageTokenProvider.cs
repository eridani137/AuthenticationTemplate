using AuthenticationTemplate.Shared.Interfaces;
using Blazored.LocalStorage;

namespace AuthenticationTemplate.Shared.Authentication;

public class LocalTokenStorage(ILocalStorageService localStorage) : ITokenStorage
{
    private const string AccessKey = "access_token";
    private const string RefreshKey = "refresh_token";
    
    private string? _cachedAccessToken;
    private string? _cachedRefreshToken;

    public async Task<string?> GetTokenAsync()
    {
        try
        {
            if (_cachedAccessToken != null) return _cachedAccessToken;
                
            var token = await localStorage.GetItemAsync<string>(AccessKey);
            _cachedAccessToken = token;
            return token;
        }
        catch (InvalidOperationException ex) when (ex.Message.Contains("JavaScript interop"))
        {
            return null;
        }
    }

    public async Task<string?> GetRefreshTokenAsync()
    {
        try
        {
            if (_cachedRefreshToken != null) return _cachedRefreshToken;
                
            var token = await localStorage.GetItemAsync<string>(RefreshKey);
            _cachedRefreshToken = token;
            return token;
        }
        catch (InvalidOperationException ex) when (ex.Message.Contains("JavaScript interop"))
        {
            return null;
        }
    }

    public async Task StoreTokensAsync(string accessToken, string refreshToken)
    {
        try
        {
            _cachedAccessToken = accessToken;
            _cachedRefreshToken = refreshToken;
            await localStorage.SetItemAsync(AccessKey, accessToken);
            await localStorage.SetItemAsync(RefreshKey, refreshToken);
        }
        catch (InvalidOperationException ex) when (ex.Message.Contains("JavaScript interop"))
        {
            _cachedAccessToken = accessToken;
            _cachedRefreshToken = refreshToken;
        }
    }

    public async Task ClearTokensAsync()
    {
        try
        {
            _cachedAccessToken = null;
            _cachedRefreshToken = null;
            
            await Task.WhenAll(
                localStorage.RemoveItemAsync(AccessKey).AsTask(),
                localStorage.RemoveItemAsync(RefreshKey).AsTask()
            );
        }
        catch (InvalidOperationException ex) when (ex.Message.Contains("JavaScript interop"))
        {
            _cachedAccessToken = null;
            _cachedRefreshToken = null;
        }
    }
}
