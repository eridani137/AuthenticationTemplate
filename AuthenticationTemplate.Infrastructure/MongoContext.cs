using Microsoft.Extensions.Configuration;
using MongoDB.Driver;

namespace AuthenticationTemplate.Infrastructure;

public class MongoContext
{
    private readonly IMongoDatabase _database;
    
    public MongoContext(IMongoClient client, IConfiguration configuration)
    {
        var connectionString = configuration.GetConnectionString("MongoDb");
        var mongoUrl = MongoUrl.Create(connectionString);
        var databaseName = mongoUrl.DatabaseName;
        _database = client.GetDatabase(databaseName);
    }
    
    public IMongoCollection<T> GetCollection<T>(string name)
    {
        return _database.GetCollection<T>(name);
    }
}