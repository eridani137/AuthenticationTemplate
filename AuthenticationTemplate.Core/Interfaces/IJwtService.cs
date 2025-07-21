using AuthenticationTemplate.Core.Entities;
using AuthenticationTemplate.Shared.DTOs;

namespace AuthenticationTemplate.Core.Interfaces;

public interface IJwtService
{
    AuthResponse GenerateKeyPair(ApplicationUser user);
    string GenerateToken(ApplicationUser user);
}