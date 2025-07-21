using System.Security.Claims;
using AuthenticationTemplate.Core.Filters;
using AuthenticationTemplate.Core.Interfaces;
using AuthenticationTemplate.Shared.DTOs;
using Carter;

namespace AuthenticationTemplate.Auth.Api.Endpoints;

public class Authentification : ICarterModule
{
    public void AddRoutes(IEndpointRouteBuilder app)
    {
        var group = app.MapGroup("/auth")
            .WithTags("Аутентификация");

        group.MapPost("/register",
                (RegisterRequest request, IAuthentificationService service) => service.Register(request))
            .AddEndpointFilter<ValidationFilter<RegisterRequest>>()
            .Produces(StatusCodes.Status200OK)
            .Produces(StatusCodes.Status400BadRequest)
            .WithName("Регистрация");

        group.MapPost("/login", (LoginRequest request, IAuthentificationService service) => service.Login(request))
            .AddEndpointFilter<ValidationFilter<LoginRequest>>()
            .Produces<AuthResponse>()
            .Produces(StatusCodes.Status401Unauthorized)
            .Produces(StatusCodes.Status400BadRequest)
            .Produces(StatusCodes.Status404NotFound)
            .Produces(StatusCodes.Status428PreconditionRequired)
            .Produces(StatusCodes.Status429TooManyRequests)
            .WithName("Авторизация");

        group.MapPost("/refresh",
                (RefreshTokenRequest request, IAuthentificationService service) => service.RefreshToken(request))
            .AddEndpointFilter<ValidationFilter<RefreshTokenRequest>>()
            .Produces<AuthResponse>()
            .Produces(StatusCodes.Status401Unauthorized)
            .WithName("Обновление токена доступа");

        group.MapPost("/logout", (ClaimsPrincipal user, IAuthentificationService service) => service.Logout(user))
            .RequireAuthorization()
            .Produces(StatusCodes.Status200OK)
            .Produces(StatusCodes.Status401Unauthorized)
            .WithName("Выход");


        var authenticator = group.MapGroup("2fa")
            .WithTags("Управление 2FA")
            .RequireAuthorization();

        authenticator.MapGet("/",
                (ClaimsPrincipal claimsPrincipal, IAuthentificationService service) =>
                    service.Get2FaStatus(claimsPrincipal))
            .Produces(StatusCodes.Status200OK)
            .Produces(StatusCodes.Status401Unauthorized)
            .WithName("Получить статус 2FA");

        authenticator.MapGet("/setup",
                (ClaimsPrincipal claimsPrincipal, IAuthentificationService service, IConfiguration configuration) =>
                    service.Setup2Fa(claimsPrincipal, configuration))
            .Produces<Setup2FaRequest>()
            .Produces(StatusCodes.Status401Unauthorized)
            .WithName("Настроить аутентификатор");

        authenticator.MapPost("/enable",
                (AuthenticatorCodeRequest request, ClaimsPrincipal claimsPrincipal, IAuthentificationService service) =>
                    service.Enable2Fa(request, claimsPrincipal))
            .AddEndpointFilter<ValidationFilter<AuthenticatorCodeRequest>>()
            .Produces<RecoveryCodesResponse>()
            .Produces(StatusCodes.Status400BadRequest)
            .Produces(StatusCodes.Status401Unauthorized)
            .WithName("Включить 2FA");

        authenticator.MapPost("/disable",
                (AuthenticatorCodeRequest request, ClaimsPrincipal claimsPrincipal, IAuthentificationService service) =>
                    service.Disable2Fa(request, claimsPrincipal))
            .AddEndpointFilter<ValidationFilter<AuthenticatorCodeRequest>>()
            .Produces(StatusCodes.Status200OK)
            .Produces(StatusCodes.Status401Unauthorized)
            .Produces(StatusCodes.Status500InternalServerError)
            .WithName("Отключить 2FA");

        authenticator.MapGet("/recovery-codes",
                (ClaimsPrincipal claimsPrincipal, IAuthentificationService service) =>
                    service.GenerateRecoveryCodes(claimsPrincipal))
            .Produces<RecoveryCodesResponse>()
            .Produces(StatusCodes.Status400BadRequest)
            .Produces(StatusCodes.Status401Unauthorized)
            .WithName("Сгенерировать коды восстановления");
    }
}