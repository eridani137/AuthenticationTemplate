using System.Net;
using System.Net.Http.Headers;
using Microsoft.AspNetCore.Components;

namespace AuthenticationTemplate.Shared.Authentication;

public class AuthenticationMessageHandler(
    CustomAuthenticationStateProvider authStateProvider,
    NavigationManager navigationManager)
    : DelegatingHandler
{
    protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        if (!string.IsNullOrEmpty(authStateProvider.Token))
        {
            if (CustomAuthenticationStateProvider.IsTokenExpired(authStateProvider.Token))
            {
                await authStateProvider.MarkUserAsLoggedOut();
                
                _ = Task.Run(() => 
                {
                    navigationManager.NavigateTo("/login",true);
                }, cancellationToken);
                
                return new HttpResponseMessage(HttpStatusCode.Unauthorized);
            }
            
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", authStateProvider.Token);
        }

        var response = await base.SendAsync(request, cancellationToken);

        // if (response.StatusCode == HttpStatusCode.Unauthorized)
        // {
        //     await customAuthStateProvider.MarkUserAsLoggedOut();
        //     
        //     _ = Task.Run(() => 
        //     {
        //         var currentUri = navigationManager.Uri;
        //         if (!currentUri.EndsWith("/login", StringComparison.OrdinalIgnoreCase))
        //         {
        //             navigationManager.NavigateTo("/login", true);
        //         }
        //     }, cancellationToken);
        // } // TODO
        
        return response;
    }
}