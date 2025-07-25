namespace AuthenticationTemplate.Shared.Interfaces;

public interface ITokenStorage
{
    Task<string?> GetTokenAsync();
    Task<string?> GetRefreshTokenAsync();
    Task StoreTokensAsync(string accessToken, string refreshToken);
    Task ClearTokensAsync();
}