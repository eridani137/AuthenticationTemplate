using Microsoft.AspNetCore.Identity;

namespace AuthenticationTemplate.Shared.Extensions;

public static class ValidationExtensions
{
    public static Dictionary<string, string[]> GetIdentityErrors(this IEnumerable<IdentityError> errors)
    {
        return errors
            .GroupBy(e => e.Code)
            .ToDictionary(
                g => g.Key,
                g => g.Select(e => e.Description).ToArray()
            );
    }
}