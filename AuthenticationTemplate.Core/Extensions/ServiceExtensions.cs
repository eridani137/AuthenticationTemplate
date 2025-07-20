using AuthenticationTemplate.Core.Services;
using AuthenticationTemplate.Shared.Validations.Validators.User;
using FluentValidation;
using Microsoft.Extensions.DependencyInjection;

namespace AuthenticationTemplate.Core.Extensions;

public static class ServiceExtensions
{
    public static IServiceCollection AddApplication(this IServiceCollection services)
    {
        services.AddValidatorsFromAssemblyContaining<LoginValidator>();

        services.AddScoped<JwtService>();

        return services;
    }
}