using System.Text.Json;
using AuthenticationTemplate.Shared.DTOs;
using Microsoft.AspNetCore.Mvc;

namespace AuthenticationTemplate.AdminPanel;

public static class AuthExtensions
{
    public static async Task<ClientAuthResponse?> HasRequired2FaCode(this HttpResponseMessage response)
    {
        var problem = await response.Content
            .ReadFromJsonAsync<ProblemDetails>(new JsonSerializerOptions
            {
                PropertyNameCaseInsensitive = true
            });
        
        if (problem is not null)
        {
            if (problem.Extensions.TryGetValue("2FARequired", out var obj) &&
                obj is JsonElement { ValueKind: JsonValueKind.True })
            {
                return new ClientAuthResponse(null, true, response.StatusCode, problem.Detail);
            }
        }

        return null;
    }
}