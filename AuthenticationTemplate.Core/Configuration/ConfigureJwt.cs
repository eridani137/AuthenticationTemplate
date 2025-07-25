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
                    ValidateIssuerSigningKey = true
                };

                options.Events = new JwtBearerEvents()
                {
                    OnTokenValidated = async context =>
                    {
                        var signInManager = context.HttpContext.RequestServices
                            .GetRequiredService<SignInManager<ApplicationUser>>();
                        var user = await signInManager.ValidateSecurityStampAsync(context.Principal);
                        if (user == null)
                        {
                            context.Fail("Токен недействителен");
                        }
                    }
                };
            });

        builder.Services.AddAuthorization();
    }
}