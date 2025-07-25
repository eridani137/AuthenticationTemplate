using AspNetCore.Identity.Mongo;
using AuthenticationTemplate.Shared.Entities;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using MongoDB.Driver;

namespace AuthenticationTemplate.Infrastructure;

public static class ServiceExtensions
{
    public static IServiceCollection AddMongoDb(this IServiceCollection services, IConfiguration configuration)
    {
        services.AddSingleton<IMongoClient>(_ => new MongoClient(configuration.GetConnectionString("MongoDb")));
        
        // services.AddScoped<MongoContext>(); // TODO

        return services;
    }

    public static IServiceCollection AddIdentity(this IServiceCollection services, IConfiguration configuration)
    {
        services.AddIdentityMongoDbProvider<ApplicationUser>(identity =>
        {
            identity.Password.RequiredLength = 8;
            identity.Password.RequireDigit = true;
            identity.Password.RequireLowercase = true;
            identity.Password.RequireNonAlphanumeric = true;
            identity.Password.RequireUppercase = true;
            identity.Password.RequiredUniqueChars = 1;

            identity.Tokens.AuthenticatorTokenProvider = TokenOptions.DefaultAuthenticatorProvider;
            identity.SignIn.RequireConfirmedAccount = false;
        }, mongo =>
        {
            mongo.ConnectionString = configuration.GetConnectionString("MongoDb");
            mongo.UsersCollection = "users";
            mongo.RolesCollection = "roles";
        });

        return services;
    }
}