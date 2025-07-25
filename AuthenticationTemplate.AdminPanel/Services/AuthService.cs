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
            if (await response.HasRequired2FaCode() is { } required2FaCode)
            {
                return required2FaCode;
            }
        }

        if (!response.IsSuccessStatusCode)
            return new ClientAuthResponse(null, false, response.StatusCode, "Ошибка авторизации");

        var authResponse = await response.Content.ReadFromJsonAsync<AuthResponse>();

        return new ClientAuthResponse(authResponse, false, response.StatusCode, null);
    }

    public static async Task<AuthResponse?> RefreshToken(HttpClient client, RefreshTokenRequest request)
    {
        var response = await client.PostAsJsonAsync($"{Endpoint}/refresh-token", request);

        if (!response.IsSuccessStatusCode) return null;

        return await response.Content.ReadFromJsonAsync<AuthResponse>();
    }
}