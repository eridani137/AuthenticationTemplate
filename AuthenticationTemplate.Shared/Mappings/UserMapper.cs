using AuthenticationTemplate.Core.Entities;
using AuthenticationTemplate.Shared.DTOs.User;

namespace AuthenticationTemplate.Shared.Mappings;

public static class UserMapper
{
    public static ApplicationUser Map(this RegistrationDto dto)
    {
        return new ApplicationUser()
        {
            UserName = dto.Username
        };
    }
}