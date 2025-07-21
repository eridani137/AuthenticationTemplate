using AuthenticationTemplate.Shared.DTOs;
using AuthenticationTemplate.Shared.Validations.Abstractions;

namespace AuthenticationTemplate.Shared.Validations.Validators.User;

public class Setup2FaValidator : BaseValidator<Enable2FaRequest>
{
    public Setup2FaValidator()
    {
        RuleFor(x => x.Code).Valid2FaCode();
    }
}