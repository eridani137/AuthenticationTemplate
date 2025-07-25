using AuthenticationTemplate.Shared.DTOs;
using AuthenticationTemplate.Shared.Validations.Abstractions;
using FluentValidation;

namespace AuthenticationTemplate.Shared.Validations.Validators.User;

public class ChangePasswordValidator : BaseValidator<ChangePasswordRequest>
{
    public ChangePasswordValidator()
    {
        RuleFor(x => x.CurrentPassword).ValidPassword();
        RuleFor(x => x.NewPassword)
            .ValidPassword()
            .Equal(x => x.CurrentPassword).WithMessage("Задайте другой пароль");
        RuleFor(x => x.ConfirmNewPassword)
            .NotEmpty().WithMessage("Подтвердите введенный пароль")
            .Equal(x => x.NewPassword).WithMessage("Пароли не совпадают");
    }
}