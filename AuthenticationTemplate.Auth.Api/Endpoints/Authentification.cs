using AuthenticationTemplate.Application;
using AuthenticationTemplate.Core.Entities;
using AuthenticationTemplate.Shared.DTOs.User;
using AuthenticationTemplate.Shared.Mappings;
using Carter;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;

namespace AuthenticationTemplate.Auth.Api.Endpoints;

public class Authentification : ICarterModule
{
    public void AddRoutes(IEndpointRouteBuilder app)
    {
        var group = app.MapGroup("/auth")
            .WithTags("Аутентификация");

        group.MapPost("/register",
                async (RegistrationDto dto, UserManager<ApplicationUser> userManager) =>
                {
                    var user = dto.Map();

                    var result = await userManager.CreateAsync(user, dto.Password);

                    if (result.Succeeded)
                    {
                        return Results.Created($"/users/{user.Id}", user.Id);
                    }

                    var identityErrors = result.Errors
                        .GroupBy(e => e.Code)
                        .ToDictionary(
                            g => g.Key,
                            g => g.Select(e => e.Description).ToArray()
                        );

                    return Results.ValidationProblem(identityErrors);
                })
            .AddEndpointFilter<ValidationFilter<RegistrationDto>>();
    }
}