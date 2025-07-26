using AuthenticationTemplate.Shared.DTOs;
using AuthenticationTemplate.Shared.Validations.Abstractions;

namespace AuthenticationTemplate.Shared.Validations.Validators.User;

public class LoginValidator : BaseValidator<LoginRequest>
{
    public LoginValidator()
    {
        RuleFor(x => x.Username).ValidUsername();
        RuleFor(x => x.Password).ValidPassword();
        When(x => !string.IsNullOrWhiteSpace(x.TwoFactorCode), () =>
        {
            RuleFor(x => x.TwoFactorCode!).ValidTwoFactorCode();
        });
    }
}