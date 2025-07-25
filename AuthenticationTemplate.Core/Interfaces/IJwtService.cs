using AuthenticationTemplate.Shared.DTOs;
using AuthenticationTemplate.Shared.Entities;

namespace AuthenticationTemplate.Core.Interfaces;

public interface IJwtService
{
    AuthResponse GenerateKeyPair(ApplicationUser user, IEnumerable<string> roleNames);
    string GenerateToken(ApplicationUser user, IEnumerable<string> roleNames);
}