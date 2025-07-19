using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using AuthenticationTemplate.Core.Configs;
using AuthenticationTemplate.Core.Entities;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;

namespace AuthenticationTemplate.Application.Services;

public class JwtService(IOptions<JwtConfig>  jwtConfig)
{
    public KeyPair GenerateKeyPair(ApplicationUser user)
    {
        var accessToken = GenerateToken(user);
        var refreshToken = GenerateRefreshToken(user);
        
        return new KeyPair(accessToken, refreshToken);
    }
    
    public string GenerateToken(ApplicationUser user)
    {
        var tokenHandler = new JwtSecurityTokenHandler();
        var secret = Encoding.ASCII.GetBytes(jwtConfig.Value.Secret);

        var claims = new List<Claim>
        {
            new(JwtRegisteredClaimNames.Sub, user.Id.ToString()),
            new(JwtRegisteredClaimNames.Nickname, user.UserName!),
            new(JwtRegisteredClaimNames.Jti, Guid.CreateVersion7().ToString())
        };
        
        claims.AddRange(user.Roles.Select(role => new Claim(ClaimTypes.Role, role)));

        var tokenDescriptor = new SecurityTokenDescriptor()
        {
            Subject = new ClaimsIdentity(claims),
            Expires = DateTime.UtcNow.Add(jwtConfig.Value.AccessTokenDuration),
            Issuer = jwtConfig.Value.Issuer,
            Audience = jwtConfig.Value.Audience,
            SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(secret), SecurityAlgorithms.HmacSha256Signature)
        };
        
        var token = tokenHandler.CreateToken(tokenDescriptor);
        var jwt = tokenHandler.WriteToken(token);
        
        return jwt;
    }

    public string GenerateRefreshToken(ApplicationUser user)
    {
        var refreshToken = Convert.ToBase64String(RandomNumberGenerator.GetBytes(64));
        
        user.RefreshToken = refreshToken;
        user.RefreshTokenExpiryTime = DateTime.UtcNow.Add(jwtConfig.Value.RefreshTokenDuration);

        return refreshToken;
    }
}

public record KeyPair(string AccessToken, string RefreshToken);