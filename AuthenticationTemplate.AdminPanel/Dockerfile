FROM mcr.microsoft.com/dotnet/aspnet:9.0 AS base
WORKDIR /app
EXPOSE 5566

FROM mcr.microsoft.com/dotnet/sdk:9.0 AS build
ARG BUILD_CONFIGURATION=Release

ENV DOTNET_EnableBuildStaticWebAssets=true

WORKDIR /src
COPY ["AuthenticationTemplate.AdminPanel/AuthenticationTemplate.AdminPanel.csproj", "AuthenticationTemplate.AdminPanel/"]
COPY ["AuthenticationTemplate.Core/AuthenticationTemplate.Core.csproj", "AuthenticationTemplate.Core/"]
COPY ["AuthenticationTemplate.Shared/AuthenticationTemplate.Shared.csproj", "AuthenticationTemplate.Shared/"]

RUN dotnet restore "AuthenticationTemplate.AdminPanel/AuthenticationTemplate.AdminPanel.csproj"

COPY . .
WORKDIR "/src/AuthenticationTemplate.AdminPanel"
RUN dotnet publish \
    -c $BUILD_CONFIGURATION \
    --no-self-contained \
    -o /app/publish \
    -p:StaticWebAssetsEnabled=true

FROM base AS final
WORKDIR /app

COPY --from=build /app/publish/ .

ENTRYPOINT ["dotnet", "AuthenticationTemplate.AdminPanel.dll"]
