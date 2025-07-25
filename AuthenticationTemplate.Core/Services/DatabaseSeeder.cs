using AspNetCore.Identity.Mongo.Model;
using AuthenticationTemplate.Core.Interfaces;
using AuthenticationTemplate.Shared.Entities;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;

namespace AuthenticationTemplate.Core.Services;

public class DatabaseSeeder(
    RoleManager<MongoRole> roleManager,
    UserManager<ApplicationUser> userManager,
    IConfiguration configuration,
    ILogger<DatabaseSeeder> logger)
    : IDatabaseSeeder
{
    public async Task Seed()
    {
        await SeedRolesAsync();
        await SeedRootUserAsync();
    }

    private async Task SeedRolesAsync()
    {
        string[] roleNames = ["User", "Editor", "Admin"];

        foreach (var roleName in roleNames)
        {
            if (await roleManager.RoleExistsAsync(roleName)) continue;

            var result = await roleManager.CreateAsync(new MongoRole(roleName));
            if (result.Succeeded) continue;
            var errors = string.Join(", ", result.Errors.Select(e => e.Description));
            logger.LogError("Ошибка при создании роли '{RoleName}'. {Errors}", roleName, errors);
        }
    }

    private async Task SeedRootUserAsync()
    {
        const string rootUsername = "root";
        var rootPassword = configuration["RootUser:Password"];

        if (string.IsNullOrWhiteSpace(rootUsername) || string.IsNullOrWhiteSpace(rootPassword))
        {
            logger.LogWarning("Данные для root-пользователя (имя или пароль) не заданы в конфигурации. Создание пропущено.");
            return;
        }

        var rootUser = await userManager.FindByNameAsync(rootUsername);
        if (rootUser is null)
        {
            rootUser = new ApplicationUser { UserName = rootUsername };

            var result = await userManager.CreateAsync(rootUser, rootPassword);
            if (!result.Succeeded)
            {
                var errors = string.Join(", ", result.Errors.Select(e => e.Description));
                logger.LogError("Ошибка при создании root-пользователя. {Errors}", errors);
                return;
            }

            logger.LogInformation("root-пользователь '{UserName}' успешно создан.", rootUsername);
        }

        var allRoles = roleManager.Roles.Select(r => r.Name).ToList();
        foreach (var roleName in allRoles)
        {
            if (roleName is not null && !await userManager.IsInRoleAsync(rootUser, roleName))
            {
                await userManager.AddToRoleAsync(rootUser, roleName);
            }
        }
    }
}