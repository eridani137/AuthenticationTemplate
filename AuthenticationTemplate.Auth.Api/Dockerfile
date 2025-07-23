FROM mcr.microsoft.com/dotnet/aspnet:9.0 AS base

WORKDIR /app
EXPOSE 5544
EXPOSE 55443

FROM mcr.microsoft.com/dotnet/sdk:9.0 AS build
ARG BUILD_CONFIGURATION=Release
WORKDIR /src
COPY ["AuthenticationTemplate.Auth.Api/AuthenticationTemplate.Auth.Api.csproj", "AuthenticationTemplate.Auth.Api/"]
COPY ["AuthenticationTemplate.Core/AuthenticationTemplate.Core.csproj", "AuthenticationTemplate.Core/"]
COPY ["AuthenticationTemplate.Shared/AuthenticationTemplate.Shared.csproj", "AuthenticationTemplate.Shared/"]
COPY ["AuthenticationTemplate.Application/AuthenticationTemplate.Application.csproj", "AuthenticationTemplate.Application/"]
RUN dotnet restore "AuthenticationTemplate.Auth.Api/AuthenticationTemplate.Auth.Api.csproj"
COPY . .
WORKDIR "/src/AuthenticationTemplate.Auth.Api"
RUN dotnet build "./AuthenticationTemplate.Auth.Api.csproj" -c $BUILD_CONFIGURATION -o /app/build

FROM build AS publish
ARG BUILD_CONFIGURATION=Release
RUN dotnet publish "./AuthenticationTemplate.Auth.Api.csproj" -c $BUILD_CONFIGURATION -o /app/publish /p:UseAppHost=false

FROM base AS final
WORKDIR /app
ENV HTTP_PORTS="5544" HTTPS_PORTS=""
COPY --from=publish /app/publish .
ENTRYPOINT ["dotnet", "AuthenticationTemplate.Auth.Api.dll"]
