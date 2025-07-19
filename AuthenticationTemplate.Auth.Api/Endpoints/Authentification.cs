using AuthenticationTemplate.Application;
using AuthenticationTemplate.Application.Filters;
using AuthenticationTemplate.Application.Services;
using AuthenticationTemplate.Core.Entities;
using AuthenticationTemplate.Shared.DTOs;
using AuthenticationTemplate.Shared.Extensions;
using AuthenticationTemplate.Shared.Mappings;
using Carter;
using Microsoft.AspNetCore.Identity;
using MongoDB.Driver.Linq;

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

                    return Results.Ok(new
                    {
                        Id = user.Id.ToString()
                    });
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

                    var keyPair = jwtService.GenerateKeyPair(user);
                    user.AccessFailedCount = 0;
                    await userManager.UpdateAsync(user);

                    return Results.Ok(keyPair);
                })
            .AddEndpointFilter<ValidationFilter<LoginDto>>();

        group.MapPost("/refresh",
                async (RefreshTokenDto dto, UserManager<ApplicationUser> userManager, JwtService jwtService) =>
                {
                    var user = await userManager.Users.SingleOrDefaultAsync(u => u.RefreshToken == dto.RefreshToken);

                    if (user is null || user.RefreshTokenExpiryTime <= DateTime.UtcNow)
                    {
                        return Results.Unauthorized();
                    }

                    var keyPair = jwtService.GenerateKeyPair(user);
                    user.AccessFailedCount = 0;
                    await userManager.UpdateAsync(user);

                    return Results.Ok(keyPair);
                })
            .AddEndpointFilter<ValidationFilter<RefreshTokenDto>>();
        ;
    }
}