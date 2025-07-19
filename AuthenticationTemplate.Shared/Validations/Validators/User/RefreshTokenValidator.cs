using AuthenticationTemplate.Core.Configs;
using AuthenticationTemplate.Shared.DTOs;
using AuthenticationTemplate.Shared.Validations.Abstractions;
using FluentValidation;
using Microsoft.Extensions.Options;

namespace AuthenticationTemplate.Shared.Validations.Validators.User;

public class RefreshTokenValidator : BaseValidator<RefreshTokenDto>
{
    public RefreshTokenValidator(IOptions<JwtConfig> jwtConfig)
    {
        var base64Length = Convert.ToBase64String(new byte[jwtConfig.Value.RefreshTokenLength]).Length;

        RuleFor(x => x.RefreshToken)
            .NotEmpty().WithMessage("RefreshToken обязателен")
            .Length(base64Length).WithMessage($"RefreshToken должен быть длиной {base64Length} символа");
    }
}