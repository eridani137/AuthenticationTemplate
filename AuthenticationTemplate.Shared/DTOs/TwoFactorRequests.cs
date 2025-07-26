namespace AuthenticationTemplate.Shared.DTOs;

public record SetupTwoFactorRequest(string SharedKey, string QrCode);

public record AuthenticatorCodeRequest(string Code);