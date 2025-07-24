using System.Net;
using System.Text.Json;
using AuthenticationTemplate.Shared.DTOs;
using Microsoft.AspNetCore.Mvc;

namespace AuthenticationTemplate.AdminPanel.Services;

public class AuthService(HttpClient client)
{
    private const string Endpoint = "/auth";

    public async Task<ClientAuthResponse> Login(LoginRequest request)
    {
        var response = await client.PostAsJsonAsync($"{Endpoint}/login", request);

        if (response.StatusCode == HttpStatusCode.Unauthorized)
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
        }
        
        if (!response.IsSuccessStatusCode) return new ClientAuthResponse(null, false, response.StatusCode, "Ошибка авторизации");

        var authResponse = await response.Content.ReadFromJsonAsync<AuthResponse>();

        return new ClientAuthResponse(authResponse, false, response.StatusCode, null);
    }
}