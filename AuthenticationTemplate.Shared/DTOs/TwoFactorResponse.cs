namespace AuthenticationTemplate.Shared.DTOs;

public record TwoFactorStatusResponse(bool IsEnabled, int RecoveryCodesCount);