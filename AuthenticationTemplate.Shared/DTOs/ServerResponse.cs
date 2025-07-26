using System.Net;

namespace AuthenticationTemplate.Shared.DTOs;

public record ServerResponse(HttpStatusCode StatusCode, string? Message);

public record ServerOperationResponse(bool OperationStatus, string? Message);