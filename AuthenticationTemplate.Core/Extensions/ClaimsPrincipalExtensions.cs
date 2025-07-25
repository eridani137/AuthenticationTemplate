using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using AuthenticationTemplate.Shared.Entities;
using Microsoft.AspNetCore.Identity;

namespace AuthenticationTemplate.Core.Extensions;

public static class ClaimsPrincipalExtensions
{
    public static async Task<ApplicationUser?> GetUserFromPrincipalAsync(this ClaimsPrincipal userPrincipal, UserManager<ApplicationUser> userManager)
    {
        var userId = userPrincipal.FindFirstValue(ClaimTypes.NameIdentifier);
        if (string.IsNullOrEmpty(userId))
        {
            return null;
        }
        return await userManager.FindByIdAsync(userId);
    }
}