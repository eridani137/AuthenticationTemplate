using AuthenticationTemplate.Shared.DTOs.User;
using AuthenticationTemplate.Shared.Validations.Abstractions;

namespace AuthenticationTemplate.Shared.Validations.Validators.User;

public class RegisterValidator : BaseValidator<RegistrationDto>
{
    public RegisterValidator()
    {
        RuleFor(x => x.Username).ValidUsername();
        
        RuleFor(x => x.Password).ValidPassword();
    }
}