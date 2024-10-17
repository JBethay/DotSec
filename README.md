# DotSec
Common Dotnet Security Issues and Fixes, __A Note on these projects, they are mostly minimal api's designed to showcase security issues and fixes. They are not designed to be taken as architectural guides for how to structure production applications or as guidelines for how to configure auth for an application. Also note that much of this project exposes OpenAPI Swagger pages for demo, this is not something you should do in production.__

## DockerSecurity
<details>
<summary>Docker Security Details</summary>
Two identical "Hello World" APIs, each implemented with distinct Dockerfiles. The first app, **Insecure**, is based on the <a href="https://learn.microsoft.com/en-us/dotnet/core/docker/build-container">default .NET template</a> and presents several security and efficiency issues. The second app, **Secure**, features an improved Dockerfile that addresses these concerns.

### Highlights of Secure Dockerfile improvements

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

<a href="https://cwe.mitre.org/data/definitions/89.html">CWE-89</a> SQL Injection. This project demonstrates a typical SQL injection vulnerability. Navigate to <a href="http://localhost:YOURPORT/swagger/index.html">http://localhost:YOURPORT/swagger/index.html</a> to explore two endpoints: one vulnerable to SQL injection attacks and the other designed to be resistant. Use the following payload to test each endpoint and observe the differences!

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
This project demonstrates a typical <a href="https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/">BOLA</a> vulnerability, which poses a significant security risk as it allows consumers to access not only their own resources but also those of others they were not intended to access. Static code analyzers often struggle to detect this issue. The project highlights related vulnerabilities such as <a href="https://cwe.mitre.org/data/definitions/285.html">CWE-285: Improper Authorization</a> and <a href="https://cwe.mitre.org/data/definitions/639.html">CWE-639: Authorization Bypass Through User-Controlled Key</a>. To explore five endpoints, navigate to <a href="http://localhost:YOURPORT/swagger/index.html">http://localhost:YOURPORT/swagger/index.html</a>.

`/api/insecure/details`
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

## BOPLA (Broken Object Property Level Authorization)
<details>
<summary>BOPLA Details</summary>
This project demonstrates a typical <a href="https://owasp.org/API-Security/editions/2023/en/0xa3-broken-object-property-level-authorization/">BOPLA</a> vulnerability, where the API exposes excessive information and allows updates to unintended data; which allows for privilege escalation in a system. Like BOLA, this issue is often undetectable by static code analysis tools. The project highlights related vulnerabilities such as <a href="https://cwe.mitre.org/data/definitions/213.html">CWE-213: Exposure of Sensitive Information Due to Incompatible Policies</a> and <a href="https://cwe.mitre.org/data/definitions/915.html">CWE-915: Improperly Controlled Modification of Dynamically-Determined Object Attributes</a>. To explore five endpoints, navigate to <a href="http://localhost:YOURPORT/swagger/index.html">http://localhost:YOURPORT/swagger/index.html</a>.

`/api/insecure/details`

This endpoint returns the complete user object from the database, leading to excessive data exposure. Sensitive fields, such as "IsAdmin", may become visible to consumers. This could allow unauthorized users to attempt to elevate their privileges during user registration.

`/api/details`

This endpoint mitigates the data exposure issue by returning a tailored response object, which includes only the properties the API owner intends to expose—specifically, just the username.

`/token`
**Payload:**
Doesn't have the required Claim (will fail):
```json
{
  "email": "normal@normal.com",
  "password": "Password1!"
}
```
Has the required Claim:
```json
{
  "email": "admin@admin.com",
  "password": "Password1!"
}
```
This endpoint generates a token for authentication. The identity implementation in this project is not production-ready but serves to demonstrate how to address the BOPLA vulnerability.

`/api/secure/details`
This endpoint requires a valid JWT token with the "AdminAccess" claim. It employs policy-based authorization, ensuring that only users with the necessary claims can access it. Although this endpoint returns a dedicated response object that includes the "IsAdmin" field, it enhances security by restricting access to expected users.

`/api/update`
**Payload:**
```json
{
  "username": "Some username",
  "isAdmin": "A IsAdminFlag"
}
```
This endpoint allows for users to update their object. Note that this is an unauthorized endpoint and something we will touch on in the bfla (Broken Function level Authorization) project.
</details>

## Unrestricted Resource Consumption
<details>
<summary>Unrestricted Resource Consumption</summary>
<a href="https://owasp.org/API-Security/editions/2023/en/0xa4-unrestricted-resource-consumption//">Unrestricted Resource Consumption</a>, <a href="https://cwe.mitre.org/data/definitions/770.html">CWE-770: Allocation of Resources Without Limits or Throttling</a>, <a href="https://cwe.mitre.org/data/definitions/400.html">CWE-400: Uncontrolled Resource Consumption</a>, <a href="https://cwe.mitre.org/data/definitions/799.html">CWE-799: Improper Control of Interaction Frequency</a>, <a href="https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-204.pdf">"Rate Limiting (Throttling)" - Security Strategies for Microservices-based Application Systems, NIST</a>, and <a href="https://owasp.org/API-Security/editions/2023/en/0xa6-unrestricted-access-to-sensitive-business-flows/">Unrestricted Access to Sensitive Business Flows</a>. This project demonstrates various fixes to help mitigate unrestricted resource consumption and unrestricted access to sensitive business flows, an issues often overlooked by static code analysis. To run the application, execute `docker-compose build && docker-compose up`, then navigate to <a href="http://localhost:5001/">http://localhost:5001/</a>.

### Highlights improvements to mitigate the issue

- **Rate Limiting:** The application implements `sliding window` rate limiting middleware for the endpoint. While effective for single instances, a distributed system may require a more comprehensive distributed rate limiter service, presenting an interesting system design challenge (and one of my personal favorite interview questions.) This solution in particular can help alleviate pressure from Unrestricted Access to Sensitive Business Flows when combined with some form of IP filtering/bot protection.
- **Cancellation Tokens:** The endpoint now accepts a `CancellationToken`, allowing clients to cancel requests. This token can also be used to abort downstream tasks, helping to prevent long-running processes from continuing after a client disconnects.
- **Request Timeout middleware:** New Request Timeout policies have been added to the endpoint, which automatically cancel any request exceeding a specified timeout threshold. This helps manage long-running requests that could exceed expected durations.
- **Container Resource Limits:** I created a K8s `pod.yml` and `docker-compose.yml` files that impose limits on container resources (CPU, memory, etc.). This approach helps prevent node resource exhaustion in a microservice environment where auto-scaling is implemented.
</details>

## BFLA (Broken Function Level Authorization)
<details>
<summary>BFLA Details</summary>
This project demonstrates a typical <a href="https://owasp.org/API-Security/editions/2023/en/0xa5-broken-function-level-authorization/">BFLA</a> vulnerability, where the API does not secure functions and endpoints that allow a user to execute a flow despite not having the expected privilege. Like BOLA and BOPLA, this issue is often undetectable by static code analysis tools. The project highlights related vulnerabilities such as <a href="https://cwe.mitre.org/data/definitions/285.html">CWE-285: Improper Authorization</a>. To explore three endpoints, navigate to <a href="http://localhost:YOURPORT/swagger/index.html">http://localhost:YOURPORT/swagger/index.html</a>.

`/api/insecure/delete`
**Payload:**
```json
{
  "username": "basic@basic.com",
}
```
This insecure endpoint allows the deletion of any user, making it highly dangerous.

`/api/secure/delete`
**Payload:**
```json
{
  "username": "normal@normal.com",
}
```
This endpoint mitigates the risks of the first by requiring the user to authenticate with a JWT and ensuring the user is in the "Admin" role to access it. Although it performs the same function as the insecure endpoint, it is safer as it restricts access to authenticated and authorized users. It employs Role-Based Access Control (RBAC), ensuring that only users with the necessary claims can access it. Additionally, this endpoint returns a dedicated response object that includes the "IsAdmin" field, further enhancing security by confirming user roles.

`/token`
**Payload:**
Doesn't have the required role, will fail on the secure endpoint:
```json
{
  "email": "normal@normal.com",
  "password": "Password1!"
}
```
Has the required role for the secure endpoint:
```json
{
  "email": "admin@admin.com",
  "password": "Password1!"
}
```
This endpoint generates a token for authentication. Note that the identity implementation in this project is not production-ready but serves to demonstrate how to address the BFLA vulnerability.
</details>

## SSRF (Server Side Request Forgery)
<details>
<summary>SSRF Details</summary>
This project demonstrates a typical <a href="https://owasp.org/Top10/A10_2021-Server-Side_Request_Forgery_%28SSRF%29/">SSRF</a> vulnerability, where the API fails to validate a client-provided URL before making a request. Such oversight can lead to serious consequences, including exposure of sensitive data, DDoS attacks, privilege escalation, and various other exploitations. Even if the client is developed in-house, it should not be trusted on the server side. The project illustrates both In-Band SSRF, where the results of calls are returned directly to the caller, and Out-Of-Band or Blind SSRF, where results are not directly returned. Although the latter is somewhat better than the former, a skilled attacker could still compromise your system quickly. The project highlights vulnerabilities like <a href="https://cwe.mitre.org/data/definitions/918.html">CWE-918: Server-Side Request Forgery (SSRF)</a>. To explore three endpoints, navigate to <a href="http://localhost:YOURPORT/swagger/index.html">http://localhost:YOURPORT/swagger/index.html</a>.

`/api/inband`
**Payload:**
```uri=https://www.google.com```
This insecure endpoint makes a request to any URI provided by the client and returns the response if successful, demonstrating an In-Band SSRF vulnerability.

`/api/outofbad`
**Payload:**
```uri=https://www.google.com```
This insecure endpoint makes a request to any URI provided by the client and returns an OK 200 response if successful, demonstrating an Out-Of-Band or Blind SSRF vulnerability. While slightly better than the first type, it remains extremely dangerous.

`/api/secured`
**Payload:**
```uri=https://www.google.com:443```
This secured endpoint makes a request to any URI provided by the client but first: (1) converts the string URI into a safe URI type in C#, performing sanitization checks; (2) compares the scheme, host, and port against allowed lists to validate the request; (3) makes the request using a custom secure HttpClient with automatic redirects disabled; and (4) returns an OK 200 response if successful.
</details>
