using AuthenticationTemplate.Core.Interfaces;
using AuthenticationTemplate.Core.Services;
using AuthenticationTemplate.Shared.Validations.Abstractions;
using AuthenticationTemplate.Shared.Validations.Validators.User;
using FluentValidation;
using Microsoft.Extensions.DependencyInjection;

namespace AuthenticationTemplate.Core.Extensions;

public static class ServiceExtensions
{
    public static IServiceCollection AddApplication(this IServiceCollection services)
    {
        services.AddValidatorsFromAssembly(typeof(BaseValidator<>).Assembly);

        services.AddScoped<IDatabaseSeeder, DatabaseSeeder>();
        services.AddScoped<IJwtService, JwtService>();
        services.AddScoped<IAuthentificationService, AuthentificationService>();

        return services;
    }
}