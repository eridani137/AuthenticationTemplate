using System.Text;
using AuthenticationTemplate.Shared.Configs;
using AuthenticationTemplate.Shared.Entities;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.Tokens;

namespace AuthenticationTemplate.Core.Configuration;

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
                    ValidateIssuerSigningKey = true,
                    ClockSkew = TimeSpan.Zero,
                };

                options.Events = new JwtBearerEvents()
                {
                    OnTokenValidated = async context =>
                    {
                        var userManager = context.HttpContext.RequestServices
                            .GetRequiredService<UserManager<ApplicationUser>>();
                        var user = await userManager.GetUserAsync(context.Principal!);
                        if (user is null || user.IsDeactivated)
                        {
                            context.Fail("Токен недействителен");
                        }
                    }
                };
            });

        builder.Services.AddAuthorization();
    }
}