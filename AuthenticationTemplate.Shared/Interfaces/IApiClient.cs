using AuthenticationTemplate.Shared.DTOs;

namespace AuthenticationTemplate.Shared.Interfaces;

public interface IApiClient
{
    Task<ClientAuthResponse> Login(LoginRequest request);
    Task<ServerResponse> ChangePassword(ChangePasswordRequest request);
    Task<TwoFactorStatusResponse?> GetTwoFactorStatus();
}