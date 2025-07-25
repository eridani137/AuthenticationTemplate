using System.Net;
using MongoDB.Bson;

namespace AuthenticationTemplate.Shared.DTOs;

public record RegisterRequest(string Username, string Password, string ConfirmPassword);

public record LoginRequest(string Username, string Password, string? TwoFactorCode)
{
    public string Username { get; set; } = Username;
    public string Password { get; set; } = Password;
    public string? TwoFactorCode { get; set; } = TwoFactorCode;
}

public record ChangePasswordRequest(string CurrentPassword, string NewPassword, string ConfirmNewPassword)
{
    public string CurrentPassword { get; set; } = CurrentPassword;
    public string NewPassword { get; set; } = NewPassword;
    public string ConfirmNewPassword { get; set; } = ConfirmNewPassword;
}

public record AuthResponse(string AccessToken, string RefreshToken);

public record ServerResponse(HttpStatusCode StatusCode, string? Message);

public record ClientAuthResponse(AuthResponse? AuthResponse, bool Require2FaCode, ServerResponse ServerResponse);

public record UserDto(ObjectId Id, string Username, IList<string> Roles, bool IsDeactivated);

public record RefreshTokenRequest(string RefreshToken);

public record Setup2FaRequest(string SharedKey, string QrCode);

public record AuthenticatorCodeRequest(string Code);

public record RecoveryCodesResponse(IEnumerable<string>? RecoveryCodes);