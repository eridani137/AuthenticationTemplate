using AuthenticationTemplate.Core.Entities;
using AuthenticationTemplate.Shared.DTOs;

namespace AuthenticationTemplate.Core.Mappings;

public static class UserMapper
{
    public static ApplicationUser Map(this RegisterRequest request)
    {
        return new ApplicationUser()
        {
            UserName = request.Username
        };
    }
}