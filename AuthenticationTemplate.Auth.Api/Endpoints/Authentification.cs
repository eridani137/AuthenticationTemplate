using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using AuthenticationTemplate.Core.Entities;
using AuthenticationTemplate.Core.Extensions;
using AuthenticationTemplate.Core.Filters;
using AuthenticationTemplate.Core.Mappings;
using AuthenticationTemplate.Core.Services;
using AuthenticationTemplate.Shared.DTOs;
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
                async (RegisterRequest dto, UserManager<ApplicationUser> userManager) =>
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
            .AddEndpointFilter<ValidationFilter<RegisterRequest>>()
            .Produces(StatusCodes.Status200OK)
            .Produces(StatusCodes.Status400BadRequest)
            .WithName("Регистрация");

        group.MapPost("/login",
                async (LoginRequest request, UserManager<ApplicationUser> userManager, JwtService jwtService) =>
                {
                    var user = await userManager.FindByNameAsync(request.Username);
                    if (user is null)
                    {
                        return Results.Problem(detail: "Пользователь не найден",
                            statusCode: StatusCodes.Status404NotFound);
                    }

                    if (await userManager.IsLockedOutAsync(user))
                    {
                        var lockoutEnd = await userManager.GetLockoutEndDateAsync(user);
                        var minutesLeft = lockoutEnd.HasValue
                            ? (int)Math.Ceiling((lockoutEnd.Value.UtcDateTime - DateTime.UtcNow).TotalMinutes)
                            : 0;

                        return Results.Problem(detail: $"Закончились попытки, повторите через {minutesLeft} мин.",
                            statusCode: StatusCodes.Status429TooManyRequests);
                    }

                    if (!await userManager.CheckPasswordAsync(user, request.Password))
                    {
                        await userManager.AccessFailedAsync(user);
                        return Results.Problem(detail: "Неверный логин или пароль",
                            statusCode: StatusCodes.Status401Unauthorized);
                    }

                    await userManager.ResetAccessFailedCountAsync(user);

                    if (await userManager.GetTwoFactorEnabledAsync(user))
                    {
                        if (string.IsNullOrWhiteSpace(request.TwoFactorCode))
                        {
                            return Results.Problem(detail: "Требуется 2FA код",
                                statusCode: StatusCodes.Status401Unauthorized);
                        }

                        var is2FaValid = await userManager.VerifyTwoFactorTokenAsync(user,
                            TokenOptions.DefaultAuthenticatorProvider, request.TwoFactorCode);

                        if (!is2FaValid)
                        {
                            await userManager.AccessFailedAsync(user);

                            return Results.Problem(detail: "Неверный 2FA код",
                                statusCode: StatusCodes.Status401Unauthorized);
                        }
                    }

                    var tokens = jwtService.GenerateKeyPair(user);
                    await userManager.UpdateAsync(user);

                    return Results.Ok(tokens);
                })
            .AddEndpointFilter<ValidationFilter<LoginRequest>>()
            .Produces<AuthResponse>()
            .Produces(StatusCodes.Status401Unauthorized)
            .Produces(StatusCodes.Status400BadRequest)
            .Produces(StatusCodes.Status404NotFound)
            .Produces(StatusCodes.Status429TooManyRequests)
            .WithName("Авторизация");

        group.MapPost("/refresh",
                async (RefreshTokenRequest request, UserManager<ApplicationUser> userManager, JwtService jwtService) =>
                {
                    var user = await userManager.Users.SingleOrDefaultAsync(u =>
                        u.RefreshToken == request.RefreshToken);

                    if (user is null)
                    {
                        return Results.Unauthorized();
                    }

                    if (user.RefreshTokenExpiryTime <= DateTime.UtcNow)
                    {
                        user.ClearRefreshToken();
                        await userManager.UpdateAsync(user);

                        return Results.Unauthorized();
                    }

                    var accessToken = jwtService.GenerateToken(user);

                    return Results.Ok(new AuthResponse(accessToken, user.RefreshToken!));
                })
            .AddEndpointFilter<ValidationFilter<RefreshTokenRequest>>()
            .Produces<AuthResponse>()
            .Produces(StatusCodes.Status401Unauthorized)
            .WithName("Обновление токена доступа");

        group.MapPost("/logout",
                async (UserManager<ApplicationUser> userManager, SignInManager<ApplicationUser> signInManager,
                    ClaimsPrincipal claimsPrincipal) =>
                {
                    var userId = claimsPrincipal.FindFirstValue(JwtRegisteredClaimNames.Sub);
                    if (userId is null) return Results.Unauthorized();

                    var user = await userManager.FindByIdAsync(userId);
                    if (user is null) return Results.Unauthorized();

                    user.ClearRefreshToken();
                    await userManager.UpdateAsync(user);

                    await signInManager.SignOutAsync();

                    return Results.Ok();
                })
            .RequireAuthorization()
            .Produces(StatusCodes.Status200OK)
            .Produces(StatusCodes.Status401Unauthorized)
            .WithName("Выход");

        var authenticator = group.MapGroup("2fa")
            .WithTags("Управление 2FA")
            .RequireAuthorization();

        authenticator.MapGet("/",
                async (ClaimsPrincipal claimsPrincipal, UserManager<ApplicationUser> userManager) =>
                {
                    var user = await userManager.GetUserAsync(claimsPrincipal);
                    if (user is null) return Results.Unauthorized();

                    return Results.Ok(new
                    {
                        Is2faEnabled = await userManager.GetTwoFactorEnabledAsync(user),
                        RecoveryCodesLeft = await userManager.CountRecoveryCodesAsync(user)
                    });
                })
            .Produces(StatusCodes.Status200OK)
            .Produces(StatusCodes.Status401Unauthorized)
            .WithName("Получить статус 2FA");

        authenticator.MapGet("/setup",
                async (ClaimsPrincipal claimsPrincipal, UserManager<ApplicationUser> userManager) =>
                {
                    var user = await userManager.GetUserAsync(claimsPrincipal);
                    if (user is null) return Results.Unauthorized();

                    await userManager.ResetAuthenticatorKeyAsync(user);
                    var key = await userManager.GetAuthenticatorKeyAsync(user);

                    var username = await userManager.GetUserNameAsync(user);
                    const string appName = "AuthenticationTemplate";
                    var authenticatorUri = $"otpauth://totp/{appName}:{username}?secret={key}&issuer={appName}";

                    return Results.Ok(new Setup2FaRequest(key!, authenticatorUri.GenerateQrCodeBase64()));
                })
            .Produces<Setup2FaRequest>()
            .Produces(StatusCodes.Status401Unauthorized)
            .WithName("Настроить аутентификатор");

        authenticator.MapPost("/enable",
                async (Enable2FaRequest request, ClaimsPrincipal claimsPrincipal,
                    UserManager<ApplicationUser> userManager) =>
                {
                    var user = await userManager.GetUserAsync(claimsPrincipal);
                    if (user is null) return Results.Unauthorized();

                    var is2FaTokenValid = await userManager.VerifyTwoFactorTokenAsync(
                        user,
                        userManager.Options.Tokens.AuthenticatorTokenProvider,
                        request.Code);

                    if (!is2FaTokenValid)
                    {
                        return Results.Problem(detail: "Код верификации недействителен",
                            statusCode: StatusCodes.Status400BadRequest);
                    }

                    await userManager.SetTwoFactorEnabledAsync(user, true);

                    var recoveryCodes = await userManager.GenerateNewTwoFactorRecoveryCodesAsync(user, 10);

                    return Results.Ok(new RecoveryCodesResponse(recoveryCodes));
                })
            .AddEndpointFilter<ValidationFilter<Enable2FaRequest>>()
            .Produces<RecoveryCodesResponse>()
            .Produces(StatusCodes.Status400BadRequest)
            .Produces(StatusCodes.Status401Unauthorized)
            .WithName("Включить 2FA");

        authenticator.MapPost("/disable",
                async (ClaimsPrincipal claimsPrincipal, UserManager<ApplicationUser> userManager) =>
                {
                    var user = await userManager.GetUserAsync(claimsPrincipal);
                    if (user is null) return Results.Unauthorized();

                    var result = await userManager.SetTwoFactorEnabledAsync(user, false);
                    if (!result.Succeeded)
                    {
                        return Results.Problem("Не удалось отключить 2FA");
                    }

                    await userManager.ResetAuthenticatorKeyAsync(user);

                    return Results.Ok();
                })
            .Produces<object>()
            .Produces(StatusCodes.Status401Unauthorized)
            .Produces(StatusCodes.Status500InternalServerError)
            .WithName("Отключить 2FA");

        authenticator.MapGet("/recovery-codes",
                async (ClaimsPrincipal claimsPrincipal, UserManager<ApplicationUser> userManager) =>
                {
                    var user = await userManager.GetUserAsync(claimsPrincipal);
                    if (user is null) return Results.Unauthorized();

                    if (!await userManager.GetTwoFactorEnabledAsync(user))
                    {
                        return Results.Problem(detail: "2FA не включен", statusCode: StatusCodes.Status400BadRequest);
                    }

                    var recoveryCodes = await userManager.GenerateNewTwoFactorRecoveryCodesAsync(user, 10);
                    return Results.Ok(new RecoveryCodesResponse(recoveryCodes));
                })
            .Produces<RecoveryCodesResponse>()
            .Produces(StatusCodes.Status400BadRequest)
            .Produces(StatusCodes.Status401Unauthorized)
            .WithName("Сгенерировать коды восстановления");
    }
}