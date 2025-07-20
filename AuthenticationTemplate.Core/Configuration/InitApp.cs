using AspNetCore.Identity.Mongo.Model;
using AuthenticationTemplate.Core.Entities;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;

namespace AuthenticationTemplate.Core.Configuration;

public class InitApp
{
    private static readonly string[] Roles = ["User", "Editor", "Admin"];

    public static async Task Init(WebApplication app)
    {
        await using var scope = app.Services.CreateAsyncScope();

        var logger = scope.ServiceProvider.GetRequiredService<ILogger<InitApp>>();
        
        var roleManager = scope.ServiceProvider.GetRequiredService<RoleManager<MongoRole>>();
        var userManager = scope.ServiceProvider.GetRequiredService<UserManager<ApplicationUser>>();

        foreach (var roleName in Roles)
        {
            if (await roleManager.RoleExistsAsync(roleName)) continue;
            var result = await roleManager.CreateAsync(new MongoRole(roleName));
            if (result.Succeeded) continue;
            
            var errors = string.Join(", ", result.Errors.Select(e => e.Description));
            logger.LogError("Ошибка создания роли '{RoleName}'. {Errors}", roleName, errors);
        }

        var rootUser = await userManager.FindByNameAsync("root");
        if (rootUser is null)
        {
            rootUser = new ApplicationUser()
            {
                UserName = "root"
            };
            
            var result = await userManager.CreateAsync(rootUser, "Qwerty123_");
            if (!result.Succeeded)
            {
                var errors = string.Join(", ", result.Errors.Select(e => e.Description));
                logger.LogError("Ошибка при создании root пользователя. {Errors}", errors);
            }
        }

        foreach (var roleName in Roles)
        {
            if (!await userManager.IsInRoleAsync(rootUser, roleName))
            {
                await userManager.AddToRoleAsync(rootUser, roleName);
            }
        }
    }
}