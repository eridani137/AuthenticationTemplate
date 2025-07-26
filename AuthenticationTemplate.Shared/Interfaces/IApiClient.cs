using AuthenticationTemplate.Shared.DTOs;

namespace AuthenticationTemplate.Shared.Interfaces;

public interface IApiClient
{
    Task<ClientAuthResponse> Login(LoginRequest request);
    Task<ServerResponse> ChangePassword(ChangePasswordRequest request);
    Task<TwoFactorStatusResponse?> GetTwoFactorStatus();
    Task<ClientSetupTwoFactorRequest> GetTwoFactorSetup();
    Task<ClientRecoveryCodesResponse> EnableTwoFactor(TwoFactorCodeRequest request);
    Task<ServerResponse> DisableTwoFactorAsync(TwoFactorCodeRequest request);
}