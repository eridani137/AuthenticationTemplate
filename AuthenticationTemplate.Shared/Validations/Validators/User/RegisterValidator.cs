using AuthenticationTemplate.Shared.DTOs;
using AuthenticationTemplate.Shared.Validations.Abstractions;
using FluentValidation;

namespace AuthenticationTemplate.Shared.Validations.Validators.User;

public class RegisterValidator : BaseValidator<RegistrationDto>
{
    public RegisterValidator()
    {
        RuleFor(x => x.Username).ValidUsername();
        RuleFor(x => x.Password).ValidPassword();

        RuleFor(x => x.ConfirmPassword)
            .Equal(x => x.Password)
            .WithMessage("Пароли не совпадают");
    }
}