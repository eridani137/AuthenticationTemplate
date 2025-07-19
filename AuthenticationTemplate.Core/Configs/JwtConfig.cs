namespace AuthenticationTemplate.Core.Configs;

public record JwtConfig
{
    public required string Secret { get; init; }
    public required string Issuer { get; init; }
    public required string Audience { get; init; }
    public required TimeSpan AccessTokenDuration { get; init; }
    public required TimeSpan RefreshTokenDuration { get; init; }
    public required int RefreshTokenLength { get; init; }
}