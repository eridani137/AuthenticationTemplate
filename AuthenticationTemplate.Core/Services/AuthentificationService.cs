using System.Security.Claims;
using AspNetCore.Identity.Mongo.Model;
using AuthenticationTemplate.Core.Extensions;
using AuthenticationTemplate.Core.Interfaces;
using AuthenticationTemplate.Shared.DTOs;
using AuthenticationTemplate.Shared.Entities;
using AuthenticationTemplate.Shared.Mappings;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Configuration;
using MongoDB.Driver.Linq;

namespace AuthenticationTemplate.Core.Services;

public class AuthentificationService(
    UserManager<ApplicationUser> userManager,
    SignInManager<ApplicationUser> signInManager,
    IJwtService jwtService) : IAuthentificationService
{
    private const string RefreshTokenProvider = "AuthenticationTemplate";
    private const string RefreshTokenName = "RefreshToken";
    private const string RefreshTokenExpiryTimeName = "RefreshTokenExpiryTime";

    public async Task<IResult> Register(RegisterRequest dto)
    {
        var user = dto.Map();
        var result = await userManager.CreateAsync(user, dto.Password);

        if (!result.Succeeded)
        {
            return Results.ValidationProblem(result.Errors.GetIdentityErrors());
        }

        return Results.Ok(new { Id = user.Id.ToString() });
    }

    public async Task<IResult> Login(LoginRequest request)
    {
        var user = await userManager.FindByNameAsync(request.Username);

        if (user is null || !await userManager.CheckPasswordAsync(user, request.Password))
        {
            if (user is not null) await userManager.AccessFailedAsync(user);

            return Results.Problem(detail: "Неверный логин или пароль", statusCode: StatusCodes.Status401Unauthorized);
        }

        if (await userManager.IsLockedOutAsync(user))
        {
            var lockoutEnd = await userManager.GetLockoutEndDateAsync(user);
            var minutesLeft = lockoutEnd.HasValue
                ? (int)Math.Ceiling((lockoutEnd.Value.UtcDateTime - DateTime.UtcNow).TotalMinutes)
                : 0;

            return Results.Problem(detail: $"Попытки исчерпаны. Повторите через {minutesLeft} мин.",
                statusCode: StatusCodes.Status429TooManyRequests);
        }

        if (await userManager.GetTwoFactorEnabledAsync(user))
        {
            if (string.IsNullOrWhiteSpace(request.TwoFactorCode))
            {
                return Results.Problem(detail: "Требуется код двухфакторной аутентификации",
                    statusCode: StatusCodes.Status401Unauthorized,
                    extensions: new Dictionary<string, object?> { { "2FARequired", true } });
            }

            if (!await userManager.VerifyTwoFactorTokenAsync(user, TokenOptions.DefaultAuthenticatorProvider,
                    request.TwoFactorCode))
            {
                await userManager.AccessFailedAsync(user);
                return Results.Problem(detail: "Код 2FA недействителен", statusCode: StatusCodes.Status401Unauthorized);
            }
        }

        await userManager.ResetAccessFailedCountAsync(user);

        var userRoles = await userManager.GetRolesAsync(user);

        var tokens = jwtService.GenerateKeyPair(user, userRoles);
        var refreshTokenExpiryTime = DateTime.UtcNow.AddDays(7);
        await userManager.SetAuthenticationTokenAsync(user, RefreshTokenProvider, RefreshTokenName,
            tokens.RefreshToken);
        await userManager.SetAuthenticationTokenAsync(user, RefreshTokenProvider, RefreshTokenExpiryTimeName,
            refreshTokenExpiryTime.ToString("o"));

        return Results.Ok(tokens);
    }

    public async Task<IResult> RefreshToken(RefreshTokenRequest request)
    {
        var user = await userManager.Users.SingleOrDefaultAsync(u =>
            u.Tokens.Any(t =>
                t.LoginProvider == RefreshTokenProvider &&
                t.Name == RefreshTokenName &&
                t.Value == request.RefreshToken));

        if (user is null) return Results.Unauthorized();

        var expiryTimeValue =
            await userManager.GetAuthenticationTokenAsync(user, RefreshTokenProvider, RefreshTokenExpiryTimeName);

        if (string.IsNullOrEmpty(expiryTimeValue) ||
            DateTime.Parse(expiryTimeValue).ToUniversalTime() <= DateTime.UtcNow)
        {
            await userManager.RemoveAuthenticationTokenAsync(user, RefreshTokenProvider, RefreshTokenName);
            await userManager.RemoveAuthenticationTokenAsync(user, RefreshTokenProvider, RefreshTokenExpiryTimeName);
            return Results.Unauthorized();
        }
        
        var userRoles = await userManager.GetRolesAsync(user);

        var accessToken = jwtService.GenerateToken(user, userRoles);
        var storedRefreshToken =
            await userManager.GetAuthenticationTokenAsync(user, RefreshTokenProvider, RefreshTokenName);

        return Results.Ok(new AuthResponse(accessToken, storedRefreshToken!));
    }
    
    public async Task<IResult> ChangePassword(ChangePasswordRequest request, ClaimsPrincipal userPrincipal)
    {
        var user = await userManager.GetUserAsync(userPrincipal);
        if (user is null) return Results.Unauthorized();
        
        var result = await userManager.ChangePasswordAsync(user, request.CurrentPassword, request.NewPassword);
        if (!result.Succeeded)
        {
            return Results.ValidationProblem(result.Errors.GetIdentityErrors());
        }
        
        return Results.Ok();
    }

    public async Task<IResult> Logout(ClaimsPrincipal userPrincipal)
    {
        var user = await userManager.GetUserAsync(userPrincipal);
        if (user is null) return Results.Unauthorized();

        await userManager.UpdateSecurityStampAsync(user);
        await userManager.RemoveAuthenticationTokenAsync(user, RefreshTokenProvider, RefreshTokenName);
        await userManager.RemoveAuthenticationTokenAsync(user, RefreshTokenProvider, RefreshTokenExpiryTimeName);

        await signInManager.SignOutAsync();

        return Results.Ok();
    }

    public async Task<IResult> GetTwoFactorStatus(ClaimsPrincipal userPrincipal)
    {
        var user = await userPrincipal.GetUserFromPrincipalAsync(userManager);
        if (user is null) return Results.Unauthorized();

        return Results.Ok(new TwoFactorStatusResponse(
            await userManager.GetTwoFactorEnabledAsync(user),
            await userManager.CountRecoveryCodesAsync(user)
        ));
    }

    public async Task<IResult> SetupTwoFactor(ClaimsPrincipal userPrincipal, IConfiguration configuration)
    {
        var user = await userPrincipal.GetUserFromPrincipalAsync(userManager);
        if (user is null) return Results.Unauthorized();

        if (await userManager.GetTwoFactorEnabledAsync(user))
        {
            return Results.Problem(detail: "2FA уже подключен", statusCode: StatusCodes.Status400BadRequest);
        }

        await userManager.ResetAuthenticatorKeyAsync(user);
        var key = await userManager.GetAuthenticatorKeyAsync(user);
        var username = await userManager.GetUserNameAsync(user);
        var applicationName = configuration["TotpApplicationName"];
        var authenticatorUri = $"otpauth://totp/{applicationName}:{username}?secret={key}&issuer={applicationName}";

        return Results.Ok(new SetupTwoFactorRequest(key!, authenticatorUri.GenerateQrCodeBase64()));
    }

    public async Task<IResult> EnableTwoFactor(AuthenticatorCodeRequest request, ClaimsPrincipal userPrincipal)
    {
        var user = await userPrincipal.GetUserFromPrincipalAsync(userManager);
        if (user is null) return Results.Unauthorized();

        var isTwoFactorTokenValid = await userManager.VerifyTwoFactorTokenAsync(
            user, userManager.Options.Tokens.AuthenticatorTokenProvider, request.Code);

        if (!isTwoFactorTokenValid)
        {
            return Results.Problem("Код верификации недействителен", statusCode: StatusCodes.Status400BadRequest);
        }

        await userManager.SetTwoFactorEnabledAsync(user, true);
        var recoveryCodes = await userManager.GenerateNewTwoFactorRecoveryCodesAsync(user, 10);

        return Results.Ok(new RecoveryCodesResponse(recoveryCodes));
    }

    public async Task<IResult> DisableTwoFactor(AuthenticatorCodeRequest request, ClaimsPrincipal userPrincipal)
    {
        var user = await userPrincipal.GetUserFromPrincipalAsync(userManager);
        if (user is null) return Results.Unauthorized();

        if (!await userManager.GetTwoFactorEnabledAsync(user))
        {
            return Results.Problem("Двухфакторная аутентификация не включена",
                statusCode: StatusCodes.Status400BadRequest);
        }

        var isTwoFactorTokenValid = await userManager.VerifyTwoFactorTokenAsync(
            user, userManager.Options.Tokens.AuthenticatorTokenProvider, request.Code);

        if (!isTwoFactorTokenValid)
        {
            return Results.Problem("Код недействителен", statusCode: StatusCodes.Status400BadRequest);
        }

        var result = await userManager.SetTwoFactorEnabledAsync(user, false);
        if (!result.Succeeded)
        {
            return Results.Problem("Не удалось отключить 2FA. Попробуйте снова.",
                statusCode: StatusCodes.Status500InternalServerError);
        }

        await userManager.ResetAuthenticatorKeyAsync(user);
        return Results.Ok();
    }

    public async Task<IResult> GenerateRecoveryCodes(ClaimsPrincipal userPrincipal)
    {
        var user = await userPrincipal.GetUserFromPrincipalAsync(userManager);
        if (user is null) return Results.Unauthorized();

        if (!await userManager.GetTwoFactorEnabledAsync(user))
        {
            return Results.Problem("2FA не включен", statusCode: StatusCodes.Status400BadRequest);
        }

        var recoveryCodes = await userManager.GenerateNewTwoFactorRecoveryCodesAsync(user, 10);
        return Results.Ok(new RecoveryCodesResponse(recoveryCodes));
    }
}