# DotSec
Common Dotnet Security Issues and Fixes, __A Note on these projects, they are mostly minimal api's designed to showcase security issues and fixes. They are not designed to be taken as architectural guides for how to structure production applications.__

## DockerSecurity
Two identical "Hello World" APIs, each implemented with distinct Dockerfiles. The first app, **Unsecure.App**, is based on the [default .NET template](https://learn.microsoft.com/en-us/dotnet/core/docker/build-container) and presents several security and efficiency issues. The second app, **Secure.App**, features an improved Dockerfile that addresses these concerns.

### Highlights of Secure.App Dockerfile improvements

- **Alpine Images:** Utilizes Alpine-based images for a smaller build and deployment footprint, optimizing resource usage.
- **Specific SHA Tags:** Implements exact SHA image tags to enhance immutability, security, and stability against potential vulnerabilities.
- **Selective File Copying:** Only copies and builds the necessary files, reducing the overall image size and attack surface.
- **Minimal Publishing:** Publishes only the required files (DLLs), excluding unnecessary executables.
- **Non-Root User:** **Critically** creates and assigns a dedicated non-root user and group, running the container under this user to improve security.
- **Defined Port Exposure:** Explicitly exposes the specified application ports, following best practices for container configuration.

## Injection

This project demonstrates a typical SQL injection vulnerability. Navigate to [http://localhost:YOURPORT/swagger/index.html](http://localhost:YOURPORT/swagger/index.html) to explore two endpoints: one vulnerable to SQL injection attacks and the other designed to be resistant. Use the following payload to test each endpoint and observe the differences!

**Payload:**
```json
{
  "username": "bad' OR '1'='1",
  "password": "bad' OR '1'='1"
}
```

> **Note:** Running this project will spin up an SQLite database.

### Highlights of Secure Endpoint Improvements

- **Parameterized Queries:** 
  - When raw SQL execution is necessary and an ORM isn't available, always use parameterized queries to prevent injection. For Entity Framework Core, this can be achieved using `FromSqlRaw` with parameters or by utilizing `FromSql`, which automatically handles parameterization.

- **Hashing Passwords and Salting:** 
  - Rule #1 of Authentication & Authorization (AuthN & AuthZ) is to never implement your own authentication. If you need to store passwords and don’t have access to a robust framework like [Microsoft Identity](https://learn.microsoft.com/en-us/aspnet/core/security/authentication/identity?view=aspnetcore-8.0), ensure you store only the hash of the password along with a random salt value. This practice helps protect against dictionary attacks by preventing attackers from easily guessing passwords or common hashes. __Also make sure you have a strong password policy when you allow users to self service accounts.__