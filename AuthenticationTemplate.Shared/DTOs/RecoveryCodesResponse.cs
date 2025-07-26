namespace AuthenticationTemplate.Shared.DTOs;

public record RecoveryCodesResponse(IEnumerable<string>? RecoveryCodes);

public record ClientRecoveryCodesResponse(RecoveryCodesResponse? RecoveryCodes, ServerResponse ServerResponse);