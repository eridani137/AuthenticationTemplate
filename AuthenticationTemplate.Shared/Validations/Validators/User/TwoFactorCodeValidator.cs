using AuthenticationTemplate.Shared.DTOs;
using AuthenticationTemplate.Shared.Validations.Abstractions;

namespace AuthenticationTemplate.Shared.Validations.Validators.User;

public class TwoFactorCodeValidator : BaseValidator<TwoFactorCodeRequest>
{
    public TwoFactorCodeValidator()
    {
        RuleFor(x => x.Code).ValidTwoFactorCode();
    }
}