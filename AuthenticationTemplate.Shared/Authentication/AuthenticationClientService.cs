using System.Net;
using System.Net.Http.Json;
using AuthenticationTemplate.Shared.DTOs;
using AuthenticationTemplate.Shared.Extensions;

namespace AuthenticationTemplate.Shared.Authentication;

public class AuthenticationClientService(HttpClient client)
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
        {
            var message = (await response.GetProblemDetails())?.Detail;
            return new ClientAuthResponse(null, false, new ServerResponse(response.StatusCode, message));
        }

        var authResponse = await response.Content.ReadFromJsonAsync<AuthResponse>();

        return new ClientAuthResponse(authResponse, false, new ServerResponse(response.StatusCode, null));
    }

    public static async Task<ClientAuthResponse> RefreshToken(HttpClient client, RefreshTokenRequest request)
    {
        var response = await client.PostAsJsonAsync($"{Endpoint}/refresh-token", request);
        
        if (!response.IsSuccessStatusCode)
        {
            var message = (await response.GetProblemDetails())?.Detail;
            return new ClientAuthResponse(null, false, new ServerResponse(response.StatusCode, message));
        }

        var authResponse = await response.Content.ReadFromJsonAsync<AuthResponse>();
        
        return new ClientAuthResponse(authResponse, false, new ServerResponse(response.StatusCode, null));
    }

    public async Task<ServerResponse> ChangePassword(ChangePasswordRequest request)
    {
        var response = await client.PostAsJsonAsync($"{Endpoint}/change-password", request);
        
        if (!response.IsSuccessStatusCode)
        {
            var message = (await response.GetProblemDetails())?.Detail;
            return new ServerResponse(response.StatusCode, message);
        }

        return new ServerResponse(response.StatusCode, null);
    }
}