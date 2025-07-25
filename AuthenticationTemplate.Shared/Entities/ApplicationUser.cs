using AspNetCore.Identity.Mongo.Model;

namespace AuthenticationTemplate.Shared.Entities;

public class ApplicationUser : MongoUser
{
    public bool IsDeactivated { get; set; }
}