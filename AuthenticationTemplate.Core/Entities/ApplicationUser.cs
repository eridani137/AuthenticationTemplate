using AspNetCore.Identity.Mongo.Model;

namespace AuthenticationTemplate.Core.Entities;

public class ApplicationUser : MongoUser
{
    public string? RefreshToken { get; set; } 
    public DateTime? RefreshTokenExpiryTime { get; set; }
}