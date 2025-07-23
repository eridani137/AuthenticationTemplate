using MongoDB.Bson;

namespace AuthenticationTemplate.Shared.DTOs;

public record RegisterRequest(string Username, string Password, string ConfirmPassword);

public record LoginRequest(string Username, string Password, string? TwoFactorCode)
{
    public string Username { get; set; } = Username;
    public string Password { get; set; } = Password;
    public string? TwoFactorCode { get; set; } = TwoFactorCode;
}

public record AuthResponse(string AccessToken, string RefreshToken);

public record UserResponse(ObjectId Id, string Username);

public record RefreshTokenRequest(string RefreshToken);

public record Setup2FaRequest(string SharedKey, string QrCode);

public record AuthenticatorCodeRequest(string Code);

public record RecoveryCodesResponse(IEnumerable<string>? RecoveryCodes);