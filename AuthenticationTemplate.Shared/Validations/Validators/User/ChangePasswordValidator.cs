using AuthenticationTemplate.Shared.DTOs;
using AuthenticationTemplate.Shared.Validations.Abstractions;
using FluentValidation;

namespace AuthenticationTemplate.Shared.Validations.Validators.User;

public class ChangePasswordValidator : BaseValidator<ChangePasswordRequest>
{
    public ChangePasswordValidator()
    {
        RuleFor(x => x.CurrentPassword)
            .NotEmpty().WithMessage("Введите текущий пароль")
            .ValidPassword();
        
        RuleFor(x => x.NewPassword)
            .NotEmpty().WithMessage("Введите новый пароль")
            .ValidPassword()
            .Must((model, newPassword) => newPassword != model.CurrentPassword)
            .WithMessage("Новый пароль не должен совпадать с текущим");

        RuleFor(x => x.ConfirmNewPassword)
            .NotEmpty().WithMessage("Подтвердите введённый пароль")
            .Equal(x => x.NewPassword).WithMessage("Пароли не совпадают");
    }
}