using System.Security.Claims;
using AuthenticationTemplate.Shared.DTOs;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Configuration;

namespace AuthenticationTemplate.Core.Interfaces;

public interface IAuthentificationService
{
    Task<IResult> Register(RegisterRequest dto);
    Task<IResult> Login(LoginRequest request);
    Task<IResult> RefreshToken(RefreshTokenRequest request);
    Task<IResult> Logout(ClaimsPrincipal userPrincipal);
    Task<IResult> GetTwoFactorStatus(ClaimsPrincipal userPrincipal);
    Task<IResult> SetupTwoFactor(ClaimsPrincipal userPrincipal, IConfiguration configuration);
    Task<IResult> EnableTwoFactor(AuthenticatorCodeRequest request, ClaimsPrincipal userPrincipal);
    Task<IResult> DisableTwoFactor(AuthenticatorCodeRequest request, ClaimsPrincipal userPrincipal);
    Task<IResult> GenerateRecoveryCodes(ClaimsPrincipal userPrincipal);
    Task<IResult> ChangePassword(ChangePasswordRequest request, ClaimsPrincipal userPrincipal);
}