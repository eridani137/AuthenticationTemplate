using System.Net.Http.Json;
using System.Text.Json;
using AuthenticationTemplate.Shared.DTOs;
using Microsoft.AspNetCore.Mvc;

namespace AuthenticationTemplate.ClientCore.Extensions;

public static class HttpResponseMessageExtensions
{
    public static async Task<ServerResponse?> GetServerResponse(this HttpResponseMessage response)
    {
        var problem = await GetProblemDetails(response);

        return problem is not null
            ? new ServerResponse(response.StatusCode, problem.Detail)
            : null;
    }

    public static async Task<(ClientAuthResponse?, ProblemDetails?)> HasRequiredTwoFactorCode(
        this HttpResponseMessage response)
    {
        var problem = await GetProblemDetails(response);

        if (problem is null) return (null, null);

        if (problem.Extensions.TryGetValue("2FARequired", out var obj) &&
            obj is JsonElement { ValueKind: JsonValueKind.True })
        {
            return (new ClientAuthResponse(null, true, new ServerResponse(response.StatusCode, problem.Detail)),
                problem);
        }

        return (null, problem);
    }

    public static async Task<ProblemDetails?> GetProblemDetails(this HttpResponseMessage response)
    {
        try
        {
            var problem = await response.Content
                .ReadFromJsonAsync<ProblemDetails>(new JsonSerializerOptions
                {
                    PropertyNameCaseInsensitive = true
                });

            return problem;
        }
        catch
        {
            return null;
        }
    }
}