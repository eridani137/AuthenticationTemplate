using AuthenticationTemplate.Core.Entities;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.DependencyInjection;

namespace AuthenticationTemplate.Application.Configuration;

public static class InitApp
{
    private static readonly string[] Roles = ["User", "Editor", "Admin"];

    public static async Task Init(WebApplication app)
    {
        await using var scope = app.Services.CreateAsyncScope();

        var roleManager = scope.ServiceProvider.GetRequiredService<RoleManager<ApplicationUser>>();
        var userManager = scope.ServiceProvider.GetRequiredService<UserManager<ApplicationUser>>();

        foreach (var role in Roles)
        {
            if (!await roleManager.RoleExistsAsync(role))
            {
                
            }
        }
    }
}