# DotSec
Common Dotnet Security Issues and Fixes, __A Note on these projects, they are mostly minimal api's designed to showcase security issues and fixes. They are not designed to be taken as architectural guides for how to structure production applications.__

## DockerSecurity
<details>
<summary>Docker Security Details</summary>
Two identical "Hello World" APIs, each implemented with distinct Dockerfiles. The first app, **Unsecure.App**, is based on the [default .NET template](https://learn.microsoft.com/en-us/dotnet/core/docker/build-container) and presents several security and efficiency issues. The second app, **Secure.App**, features an improved Dockerfile that addresses these concerns.

### Highlights of Secure.App Dockerfile improvements

- **Alpine Images:** Utilizes Alpine-based images for a smaller build and deployment footprint, optimizing resource usage.
- **Specific SHA Tags:** Implements exact SHA image tags to enhance immutability, security, and stability against potential vulnerabilities.
- **Selective File Copying:** Only copies and builds the necessary files, reducing the overall image size and attack surface.
- **Minimal Publishing:** Publishes only the required files (DLLs), excluding unnecessary executables.
- **Non-Root User:** **Critically** creates and assigns a dedicated non-root user and group, running the container under this user to improve security.
- **Defined Port Exposure:** Explicitly exposes the specified application ports, following best practices for container configuration.
</details>

## Injection
<details>
<summary>Inject Details</summary>

[CWE-89](https://cwe.mitre.org/data/definitions/89.html) SQL Injection. This project demonstrates a typical SQL injection vulnerability. Navigate to [http://localhost:YOURPORT/swagger/index.html](http://localhost:YOURPORT/swagger/index.html) to explore two endpoints: one vulnerable to SQL injection attacks and the other designed to be resistant. Use the following payload to test each endpoint and observe the differences!

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
  - Rule #1 of Authentication & Authorization (AuthN & AuthZ) is to never implement your own authentication. If you need to store passwords and don’t have access to a robust framework like [Microsoft Identity](https://learn.microsoft.com/en-us/aspnet/core/security/authentication/identity?view=aspnetcore-8.0), ensure you store only the hash of the password along with a random salt value. This practice helps protect against dictionary attacks by preventing attackers from easily guessing passwords or common hashes. __Also make sure you have a strong password policy when you allow users to self service accounts.__ Note that while this demo's SQL injection attacks, NoSQL Injection attacks are also extremely common and implemented (and fixed) in a similar manor.
</details>

## BOLA (Broken Object Level Authorization)
<details>
<summary>BOLA Details</summary>
[BOLA](https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/)[CWE-285: Improper Authorization](https://cwe.mitre.org/data/definitions/285.html) [CWE-639: Authorization Bypass Through User-Controlled Key](https://cwe.mitre.org/data/definitions/639.html). This project demonstrates a typical BOLA vulnerability. Navigate to [http://localhost:YOURPORT/swagger/index.html](http://localhost:YOURPORT/swagger/index.html) to explore 5 endpoints: 

`/api/unsecure/details`
**Payload:**
```json
{
  "id": 1
}
```
This endpoint allows you to increment the id parameter to access additional user accounts. Such vulnerabilities are often missed by static analyzers, making them a significant security risk. This endpoint does not require authentication, but even if it did, the flaw could still be exploited.

`/api/dangerous/getallusers`
Retrieves a list of all user IDs for demonstration purposes.

`/api/details`
**Payload:**
```json
{
  "userId": "Some Guid From getallusers"
}
```
This endpoint attempts to mitigate the issue by using Guid values instead of easily incremented IDs, making them harder to guess. However, similar to the previous endpoint, even with authorization, an attacker could still access additional user details with sufficient effort.

`/token`
**Payload:**
```json
{
  "email": "normal@normal.com",
  "password": "Password1!"
}
```
This endpoint generates a token for authentication. The identity implementation in this project is not production-ready but serves to demonstrate how to address the BOLA vulnerability.

`/api/secure/details`
**Payload:**
```json
{
  "userId": "Some Guid From getallusers"
}
```
This endpoint requires a valid JWT token and a valid userId Guid. It critically checks the current user's email against the email of the account details being retrieved. If they do not match, a 401 Unauthorized response is returned. While this solution improves security, further enhancements could include implementing Role-Based Access Control (RBAC) and user access policies to strengthen data protection. Overall, this last approach is significantly more secure than the initial implementation.
</details>
