
# docker build -t secure_dotnet_docker_app .
# docker run -p 5001:5141 --name secure_dotnet_docker_app secure_dotnet_docker_app

# Use the .NET SDK image based on Alpine for the build stage for a smaller footprint
# Use exact SHA for Immutability, Security, and Stability
FROM mcr.microsoft.com/dotnet/sdk:8.0-alpine@sha256:07cb8622ca6c4d7600b42b2eccba968dff4b37d41b43a9bf4bd800aa02fab117 AS build

WORKDIR /src
# Copy Only what we need
COPY ["Secure.App.csproj", "./"]
RUN dotnet restore "Secure.App.csproj"
COPY . .

# We only need the dll, not the exe
RUN dotnet publish "Secure.App.csproj" -c Release -o /app/publish /p:UseAppHost=false

# Use the .NET runtime image based on Alpine for the final stage
# Use exact SHA for Immutability, Security, and Stability
FROM mcr.microsoft.com/dotnet/aspnet:8.0-alpine@sha256:09bd97b2f28a084168e6d4e2f1c32385753cd7166c8d87af71a0dba2919d7aa2 AS final
WORKDIR /app

# Create a non-root user and make the app use that user, never run as root
RUN addgroup -S appgroup && adduser -S appuser -G appgroup
USER appuser

COPY --from=build /app/publish .

# Set the port ourselves
EXPOSE 5141
ENV ASPNETCORE_URLS=http://+:5141

ENTRYPOINT ["dotnet", "Secure.App.dll"]