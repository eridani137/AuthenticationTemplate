using System.Net;

namespace AuthenticationTemplate.Shared.DTOs;

public record AuthResponse(string AccessToken, string RefreshToken);

public record ClientAuthResponse(AuthResponse? AuthResponse, bool RequireTwoFactorCode, ServerResponse ServerResponse);

public record ServerResponse(HttpStatusCode StatusCode, string? Message);