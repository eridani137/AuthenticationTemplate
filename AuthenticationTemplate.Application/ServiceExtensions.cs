using AuthenticationTemplate.Shared.Validations.Validators.User;
using FluentValidation;
using Microsoft.Extensions.DependencyInjection;

namespace AuthenticationTemplate.Application;

public static class ServiceExtensions
{
    public static IServiceCollection AddApplication(this IServiceCollection services)
    {
        services.AddValidatorsFromAssemblyContaining<RegisterValidator>();

        return services;
    }
}