using Carter;

namespace AuthenticationTemplate.Api.Endpoints;

public class Users : ICarterModule
{
    public void AddRoutes(IEndpointRouteBuilder app)
    {
        var group = app.MapGroup("/users");

        group.MapGet("/", () => Results.Ok("Hello World!"));
    }
}