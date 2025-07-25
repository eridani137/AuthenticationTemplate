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
            .Must((model, newPassword) => newPassword != model.CurrentPassword)
            .WithMessage("Новый пароль не должен совпадать с текущим");
        RuleFor(x => x.ConfirmNewPassword)
            .NotEmpty().WithMessage("Подтвердите введенный пароль")
            .Equal(x => x.NewPassword).WithMessage("Пароли не совпадают");
    }
}