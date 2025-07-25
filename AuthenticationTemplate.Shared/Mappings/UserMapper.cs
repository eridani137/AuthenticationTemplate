using AuthenticationTemplate.Shared.DTOs;
using AuthenticationTemplate.Shared.Entities;

namespace AuthenticationTemplate.Shared.Mappings;

public static class UserMapper
{
    public static ApplicationUser Map(this RegisterRequest request)
    {
        return new ApplicationUser()
        {
            UserName = request.Username
        };
    }

    public static UserDto Map(this ApplicationUser user, IList<string> roles)
    {
        return new UserDto(user.Id, user.UserName!, roles, user.IsDeactivated);
    }
}