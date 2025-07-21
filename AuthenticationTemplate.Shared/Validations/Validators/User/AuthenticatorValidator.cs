using AuthenticationTemplate.Shared.DTOs;
using AuthenticationTemplate.Shared.Validations.Abstractions;

namespace AuthenticationTemplate.Shared.Validations.Validators.User;

public class AuthenticatorValidator : BaseValidator<AuthenticatorCodeRequest>
{
    public AuthenticatorValidator()
    {
        RuleFor(x => x.Code).Valid2FaCode();
    }
}