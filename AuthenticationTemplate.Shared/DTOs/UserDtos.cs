using MongoDB.Bson;

namespace AuthenticationTemplate.Shared.DTOs;

public record RegistrationDto(string Username, string Password);

public record LoginDto(string Username, string Password);

public record UserDto(ObjectId Id, string Username);