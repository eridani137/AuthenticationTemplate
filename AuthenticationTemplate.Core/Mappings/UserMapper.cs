using AuthenticationTemplate.Core.Entities;
using AuthenticationTemplate.Shared.DTOs;

namespace AuthenticationTemplate.Core.Mappings;

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