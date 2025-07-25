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
    Task<IResult> Get2FaStatus(ClaimsPrincipal userPrincipal);
    Task<IResult> Setup2Fa(ClaimsPrincipal userPrincipal, IConfiguration configuration);
    Task<IResult> Enable2Fa(AuthenticatorCodeRequest request, ClaimsPrincipal userPrincipal);
    Task<IResult> Disable2Fa(AuthenticatorCodeRequest request, ClaimsPrincipal userPrincipal);
    Task<IResult> GenerateRecoveryCodes(ClaimsPrincipal userPrincipal);
    Task<IResult> ChangePassword(ChangePasswordRequest request, ClaimsPrincipal userPrincipal);
}