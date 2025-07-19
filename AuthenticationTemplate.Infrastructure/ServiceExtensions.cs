using AspNetCore.Identity.Mongo;
using AuthenticationTemplate.Core.Entities;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using MongoDB.Driver;

namespace AuthenticationTemplate.Infrastructure;

public static class ServiceExtensions
{
    public static IServiceCollection AddInfrastructure(this IServiceCollection services, IConfiguration configuration)
    {
        services.AddSingleton<IMongoClient>(_ => new MongoClient(configuration.GetConnectionString("MongoDb")));
        
        services.AddScoped<MongoContext>();

        services.AddIdentityMongoDbProvider<ApplicationUser>(identityOptions =>
        {
            identityOptions.Password.RequiredLength = 8;
            identityOptions.Password.RequireDigit = true;
            identityOptions.Password.RequireLowercase = true;
            identityOptions.Password.RequireNonAlphanumeric = true;
            identityOptions.Password.RequireUppercase = true;
            identityOptions.Password.RequiredUniqueChars = 1;
        }, mongoDbOptions =>
        {
            mongoDbOptions.ConnectionString = configuration.GetConnectionString("MongoDb");
        });

        return services;
    }
}