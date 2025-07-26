namespace AuthenticationTemplate.Shared.DTOs;

public record RegisterRequest(string Username, string Password, string ConfirmPassword);

public record LoginRequest(string Username, string Password, string? TwoFactorCode)
{
    public string Username { get; set; } = Username;
    public string Password { get; set; } = Password;
    public string? TwoFactorCode { get; set; } = TwoFactorCode;
}

public record RefreshTokenRequest(string RefreshToken);