using System.Text;
using AuthenticationTemplate.Core.Configs;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.Tokens;

namespace AuthenticationTemplate.Application.Configuration;

public static class ConfigureJwt
{
    public static void Configure(WebApplicationBuilder builder)
    {
        builder.Services.Configure<JwtConfig>(builder.Configuration.GetSection(nameof(JwtConfig)));
        
        var secret = Encoding.ASCII.GetBytes(builder.Configuration["JwtConfig:Secret"]!);
        
        builder.Services.AddAuthentication(options =>
        {
            options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
            options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
            options.DefaultScheme = JwtBearerDefaults.AuthenticationScheme;
        })
        .AddJwtBearer(options =>
        {
            options.TokenValidationParameters = new TokenValidationParameters()
            {
                ValidateIssuer = true,
                ValidIssuer = builder.Configuration["JwtConfig:Issuer"],
                ValidateAudience = true,
                ValidAudience = builder.Configuration["JwtConfig:Audience"],
                ValidateLifetime = true,
                IssuerSigningKey = new SymmetricSecurityKey(secret),
                ValidateIssuerSigningKey = true
            };
        });
        
        builder.Services.AddAuthorization();
    }
}