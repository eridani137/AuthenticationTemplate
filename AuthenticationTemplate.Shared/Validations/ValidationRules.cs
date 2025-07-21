using FluentValidation;

namespace AuthenticationTemplate.Shared.Validations;

public static class ValidationRules
{
    public static IRuleBuilderOptions<T, string> ValidUsername<T>(this IRuleBuilder<T, string> rule)
    {
        return rule
            .NotEmpty().WithMessage("Введите логин");
    }
    
    public static IRuleBuilderOptions<T, string> ValidPassword<T>(this IRuleBuilder<T, string> rule)
    {
        return rule
            .NotEmpty().WithMessage("Введите пароль")
            .MinimumLength(8).WithMessage("Пароль должен содержать не менее 8 символов")
            .Matches("[A-Z]").WithMessage("Пароль должен содержать хотя бы одну заглавную букву")
            .Matches("[a-z]").WithMessage("Пароль должен содержать хотя бы одну строчную букву")
            .Matches("[0-9]").WithMessage("Пароль должен содержать хотя бы одну цифру")
            .Matches("[^a-zA-Z0-9]").WithMessage("Пароль должен содержать хотя бы один специальный символ");
    }

    public static IRuleBuilderOptions<T, string> Valid2FaCode<T>(this IRuleBuilder<T, string> rule)
    {
        return rule
            .NotEmpty().WithMessage("Введите код аутентификации")
            .MinimumLength(6).WithMessage("Код должен содержать 6 цифр");
    }
}