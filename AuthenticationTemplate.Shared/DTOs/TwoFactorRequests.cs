namespace AuthenticationTemplate.Shared.DTOs;

public record SetupTwoFactorRequest(string SharedKey, string QrCode);

public record ClientSetupTwoFactorRequest(SetupTwoFactorRequest? SetupTwoFactorRequest, ServerResponse ServerResponse);

public record TwoFactorCodeRequest(string Code)
{
    public string Code { get; set; } = Code;
}