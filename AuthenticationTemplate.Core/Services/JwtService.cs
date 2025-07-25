using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using AuthenticationTemplate.Core.Interfaces;
using AuthenticationTemplate.Shared.Configs;
using AuthenticationTemplate.Shared.DTOs;
using AuthenticationTemplate.Shared.Entities;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;

namespace AuthenticationTemplate.Core.Services;

public class JwtService(IOptions<JwtConfig> config) : IJwtService
{
    public AuthResponse GenerateKeyPair(ApplicationUser user, IEnumerable<string> roleNames)
    {
        var accessToken = GenerateToken(user, roleNames);
        var refreshToken = GenerateRefreshToken(user);

        return new AuthResponse(accessToken, refreshToken);
    }

    public string GenerateToken(ApplicationUser user, IEnumerable<string> roleNames)
    {
        var tokenHandler = new JwtSecurityTokenHandler();
        var secret = Encoding.ASCII.GetBytes(config.Value.Secret);

        var claims = new List<Claim>
        {
            new(JwtRegisteredClaimNames.Sub, user.Id.ToString()),
            new(JwtRegisteredClaimNames.Nickname, user.UserName!),
            new(JwtRegisteredClaimNames.Jti, Guid.CreateVersion7().ToString())
        };

        claims.AddRange(roleNames.Select(roleName => new Claim(ClaimTypes.Role, roleName)));

        var tokenDescriptor = new SecurityTokenDescriptor()
        {
            Subject = new ClaimsIdentity(claims),
            Expires = DateTime.UtcNow.Add(config.Value.AccessTokenDuration),
            Issuer = config.Value.Issuer,
            Audience = config.Value.Audience,
            SigningCredentials =
                new SigningCredentials(new SymmetricSecurityKey(secret), SecurityAlgorithms.HmacSha256Signature)
        };

        var token = tokenHandler.CreateToken(tokenDescriptor);
        var jwt = tokenHandler.WriteToken(token);

        return jwt;
    }

    private string GenerateRefreshToken(ApplicationUser user)
    {
        return Convert.ToBase64String(RandomNumberGenerator.GetBytes(config.Value.RefreshTokenLength));
    }
}