using AuthenticationTemplate.Shared.Configs;
using AuthenticationTemplate.Shared.DTOs;
using AuthenticationTemplate.Shared.Validations.Abstractions;
using FluentValidation;
using Microsoft.Extensions.Options;

namespace AuthenticationTemplate.Shared.Validations.Validators.User;

public class RefreshTokenValidator : BaseValidator<RefreshTokenRequest>
{
    public RefreshTokenValidator(IOptions<JwtConfig> config)
    {
        var base64Length = Convert.ToBase64String(new byte[config.Value.RefreshTokenLength]).Length;

        RuleFor(x => x.RefreshToken)
            .NotEmpty().WithMessage("RefreshToken обязателен")
            .Length(base64Length).WithMessage($"RefreshToken должен быть длиной {base64Length} символа");
    }
}