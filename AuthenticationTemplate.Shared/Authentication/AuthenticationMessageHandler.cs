using System.Net.Http.Headers;
using AuthenticationTemplate.Shared.Interfaces;
using Microsoft.AspNetCore.Components;

namespace AuthenticationTemplate.Shared.Authentication;

public class AuthenticationMessageHandler(
    ITokenStorage tokenStorage,
    NavigationManager navigation)
    : DelegatingHandler
{

    protected override async Task<HttpResponseMessage> SendAsync(
        HttpRequestMessage request,
        CancellationToken cancellationToken)
    {
        var token = await tokenStorage.GetTokenAsync();
        
        if (!string.IsNullOrEmpty(token))
        {
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
        }

        var response = await base.SendAsync(request, cancellationToken);

        // if (response.StatusCode == HttpStatusCode.Unauthorized)
        // {
        //     await tokenStorage.ClearTokensAsync();
        //     navigation.NavigateTo("/login", forceLoad: true);
        // }

        return response;
    }
}