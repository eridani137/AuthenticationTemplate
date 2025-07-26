using AuthenticationTemplate.Shared.DTOs;
using AuthenticationTemplate.Shared.Entities;
using AuthenticationTemplate.Shared.Mappings;
using Microsoft.AspNetCore.Identity;
using MongoDB.Bson;
using MongoDB.Driver.Linq;

namespace AuthenticationTemplate.AdminPanel.Services;

public class AdminService(UserManager<ApplicationUser> userManager)
{
    public async Task<List<UserDto>> GetUsers()
    {
        var users = await userManager.Users.ToListAsync() ?? [];
        var result = new List<UserDto>();
        foreach (var user in users)
        {
            var roles = await userManager.GetRolesAsync(user);
            result.Add(user.Map(roles));
        }

        return result;
    }

    public async Task<UserDto?> GetUser(ObjectId userId)
    {
        var user = await userManager.Users.FirstOrDefaultAsync(u => u.Id == userId);
        if (user is null) return null;

        var userRoles = await userManager.GetRolesAsync(user);
        return user.Map(userRoles);
    }

    public async Task<ServerOperationResponse> DeleteUser(ObjectId userId)
    {
        var user = await userManager.Users.FirstOrDefaultAsync(u => u.Id == userId);
        if (user is null) return new ServerOperationResponse(false, "Пользователь не найден");

        if (user.UserName!.Equals("root", StringComparison.OrdinalIgnoreCase))
        {
            return new ServerOperationResponse(false, "Нельзя удалить root пользователя");
        }

        var result = await userManager.DeleteAsync(user);
        if (!result.Succeeded)
        {
            return new ServerOperationResponse(false, string.Join(", ", result.Errors.Select(e => e.Description)));
        }

        return new ServerOperationResponse(true, $"Пользователь {user.UserName} удален");
    }
}