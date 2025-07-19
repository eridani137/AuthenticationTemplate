using AuthenticationTemplate.Application;
using AuthenticationTemplate.Application.Filters;
using AuthenticationTemplate.Application.Services;
using AuthenticationTemplate.Core.Entities;
using AuthenticationTemplate.Shared.DTOs;
using AuthenticationTemplate.Shared.Extensions;
using AuthenticationTemplate.Shared.Mappings;
using Carter;
using Microsoft.AspNetCore.Identity;

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

                    if (!result.Succeeded)
                    {
                        return Results.ValidationProblem(result.Errors.GetIdentityErrors());
                        
                    }

                    return Results.Created($"/users/{user.Id}", user.Id);
                })
            .AddEndpointFilter<ValidationFilter<RegistrationDto>>();

        group.MapPost("/login",
            async (LoginDto dto, UserManager<ApplicationUser> userManager, JwtService jwtService) =>
            {
                var user = await userManager.FindByNameAsync(dto.Username);
                if (user is null)
                {
                    return Results.Unauthorized();
                }

                var now = DateTime.UtcNow;
                if (user.LockoutEnd is not null)
                {
                    if (user.LockoutEnd > now)
                    {
                        var minutesLeft = (int)Math.Ceiling((user.LockoutEnd.Value.UtcDateTime - now).TotalMinutes);
                        return Results.Json(new
                        {
                            Error = $"Повторите через {minutesLeft} мин.",
                        }, statusCode: StatusCodes.Status429TooManyRequests);
                    }
                }

                var result = await userManager.CheckPasswordAsync(user, dto.Password);
                if (!result)
                {
                    await userManager.AccessFailedAsync(user);
                    return Results.Unauthorized();
                }

                await userManager.ResetAccessFailedCountAsync(user);

                return Results.Ok(new
                {
                    AccessToken = jwtService.GenerateToken(user)
                });
            })
            .AddEndpointFilter<ValidationFilter<LoginDto>>();
    }
}