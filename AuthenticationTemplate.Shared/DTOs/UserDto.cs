using MongoDB.Bson;

namespace AuthenticationTemplate.Shared.DTOs;

public record UserDto(ObjectId Id, string Username, IList<string> Roles, bool IsDeactivated);