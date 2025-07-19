using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using AuthenticationTemplate.Application.Filters;
using AuthenticationTemplate.Application.Services;
using AuthenticationTemplate.Core.Entities;
using AuthenticationTemplate.Shared.DTOs;
using AuthenticationTemplate.Shared.Extensions;
using AuthenticationTemplate.Shared.Mappings;
using Carter;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
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
            .AddEndpointFilter<ValidationFilter<RegistrationDto>>()
            .Produces(StatusCodes.Status200OK)
            .Produces(StatusCodes.Status400BadRequest)
            .WithName("Регистрация");

        group.MapPost("/login",
                async (LoginDto dto, UserManager<ApplicationUser> userManager,
                    SignInManager<ApplicationUser> signInManager, JwtService jwtService) =>
                {
                    var user = await userManager.FindByNameAsync(dto.Username);
                    if (user is null)
                    {
                        return Results.Unauthorized();
                    }

                    var result = await signInManager.PasswordSignInAsync(user, dto.Password, isPersistent: false,
                        lockoutOnFailure: true);
                    if (result.Succeeded)
                    {
                        var keyPair = jwtService.GenerateKeyPair(user);
                        await userManager.UpdateAsync(user);
                        return Results.Ok(keyPair);
                    }

                    if (!result.IsLockedOut) return Results.Unauthorized();

                    var now = DateTime.UtcNow;
                    if (user.LockoutEnd is null || !(user.LockoutEnd > now)) return Results.Unauthorized();
                    var minutesLeft = (int)Math.Ceiling((user.LockoutEnd.Value.UtcDateTime - now).TotalMinutes);

                    return Results.Json(new
                    {
                        Message = $"Повторите через {minutesLeft} мин.",
                    }, statusCode: StatusCodes.Status429TooManyRequests);
                })
            .AddEndpointFilter<ValidationFilter<LoginDto>>()
            .Produces<TokenPair>()
            .Produces(StatusCodes.Status401Unauthorized)
            .Produces(StatusCodes.Status429TooManyRequests)
            .WithName("Авторизация");

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
            .AddEndpointFilter<ValidationFilter<RefreshTokenDto>>()
            .Produces<TokenPair>()
            .Produces(StatusCodes.Status401Unauthorized)
            .WithName("Обновление токена доступа");

        group.MapPost("/logout",
                async (UserManager<ApplicationUser> userManager, ClaimsPrincipal claimsPrincipal) =>
                {
                    var userId = claimsPrincipal.FindFirstValue(JwtRegisteredClaimNames.Sub);
                    if (userId is null) return Results.Unauthorized();

                    var user = await userManager.FindByIdAsync(userId);
                    if (user is null) return Results.Unauthorized();

                    user.RefreshToken = null;
                    user.RefreshTokenExpiryTime = null;
                    await userManager.UpdateAsync(user);

                    return Results.Ok();
                })
            .RequireAuthorization()
            .Produces(StatusCodes.Status200OK)
            .Produces(StatusCodes.Status401Unauthorized)
            .WithName("Выход");
    }
}