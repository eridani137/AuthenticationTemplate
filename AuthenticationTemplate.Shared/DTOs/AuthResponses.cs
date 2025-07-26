namespace AuthenticationTemplate.Shared.DTOs;

public record AuthResponse(string AccessToken, string RefreshToken);

public record ClientAuthResponse(AuthResponse? AuthResponse, bool RequireTwoFactorCode, ServerResponse ServerResponse);