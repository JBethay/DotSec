# DotSec
Common Dotnet Security Issues and Fixes

## DockerSecurity
Two identical "Hello World" APIs, each implemented with distinct Dockerfiles. The first app, **Unsecure.App**, is based on the [default .NET template](https://learn.microsoft.com/en-us/dotnet/core/docker/build-container) and presents several security and efficiency issues. The second app, **Secure.App**, features an improved Dockerfile that addresses these concerns.

### Highlights of Secure.App Dockerfile improvements

- **Alpine Images:** Utilizes Alpine-based images for a smaller build and deployment footprint, optimizing resource usage.
- **Specific SHA Tags:** Implements exact SHA image tags to enhance immutability, security, and stability against potential vulnerabilities.
- **Selective File Copying:** Only copies and builds the necessary files, reducing the overall image size and attack surface.
- **Minimal Publishing:** Publishes only the required files (DLLs), excluding unnecessary executables.
- **Non-Root User:** **Critically** creates and assigns a dedicated non-root user and group, running the container under this user to improve security.
- **Defined Port Exposure:** Explicitly exposes the specified application ports, following best practices for container configuration.
