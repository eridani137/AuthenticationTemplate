using AuthenticationTemplate.Shared.DTOs;
using AuthenticationTemplate.Shared.Entities;
using AuthenticationTemplate.Shared.Mappings;
using Microsoft.AspNetCore.Identity;
using MongoDB.Bson;
using MongoDB.Driver.Linq;

namespace AuthenticationTemplate.AdminPanel.Services;

public class UserService(UserManager<ApplicationUser> userManager)
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
}