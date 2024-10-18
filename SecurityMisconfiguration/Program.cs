using System.Diagnostics;
using Microsoft.AspNetCore.Antiforgery;
using Microsoft.OpenApi.Models;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddAntiforgery();
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen(c =>
{
    c.SwaggerDoc("v1", new OpenApiInfo { Title = "BOLA API", Version = "v1" });
    c.OperationFilter<AntiForgeryTokenHeaderParameter>();
});

var app = builder.Build();
app.UseAntiforgery();

//NEVER DO THIS, IF YOU DO YOU ARE ASKING FOR PROBLEMS. This is here to show what could happen if a user opens the file uploaded to storage.
static async Task<string> HyperDangerousShellExecution(string filePath)
{
    var processInfo = new ProcessStartInfo
    {
        FileName = "/bin/sh",
        Arguments = $"-c \"cat {filePath}\"",  // Run the cat command with the file path
        RedirectStandardOutput = true,
        UseShellExecute = false,
        CreateNoWindow = true
    };

    using var process = Process.Start(processInfo) ?? throw new Exception("Failed to start process.");
    var result = await process.StandardOutput.ReadToEndAsync();
    await process.WaitForExitAsync();
    return result;
}

app.MapPost("/upload/dangerous", async (IFormFile file) =>
{
    try {
        if (file == null || file.Length == 0) 
            return Results.BadRequest();

        var path = Path.Combine(Directory.GetCurrentDirectory(), "uploads");

        if (!Directory.Exists(path))
            Directory.CreateDirectory(path);

        var filePath = Path.Combine(path, file.FileName);

        using var stream = new FileStream(filePath, FileMode.Create);
        await file.CopyToAsync(stream);
        stream.Dispose();

        var content = await HyperDangerousShellExecution(filePath);

        return Results.Ok(new 
        { 
            FilePath = filePath, 
            Content = content 
        });
    } catch (Exception e) {
        return Results.Problem(statusCode:500);
    }
}).DisableAntiforgery().WithName("insecure upload").WithOpenApi();

app.MapPost("/upload/safe", async (IFormFile file) =>
{
    try {
        const long maxFileSize = 1024 * 1024; //1MB
        HashSet<string> hashSet  = [ ".txt" ];

        if (file == null || file.Length == 0 || file.Length > maxFileSize) 
            return Results.BadRequest();

        var extension = Path.GetExtension(file.FileName).ToLowerInvariant();

        if(!hashSet.Contains(extension))
            return Results.BadRequest();

        var path = Path.Combine(Directory.GetCurrentDirectory(), "uploads");

        if (!Directory.Exists(path))
            Directory.CreateDirectory(path);

        //Don't save the file extension
        var filePath = Path.Combine(path, Path.GetFileNameWithoutExtension(file.FileName));

        using var stream = new FileStream(filePath, FileMode.Create);
        await file.CopyToAsync(stream);
        stream.Dispose();

        var content = await HyperDangerousShellExecution(filePath);

        return Results.Ok(new 
        { 
            FilePath = filePath, 
            Content = content 
        });
    } catch (Exception e) {
        return Results.Problem(statusCode:500);
    }
}).WithName("more secure upload").WithOpenApi();

app.MapGet("/token", (IAntiforgery forgeryService, HttpContext context) =>
{
    var tokens = forgeryService.GetAndStoreTokens(context);
    var xsrfToken = tokens.RequestToken!;
    return TypedResults.Content(xsrfToken, "text/plain");
});

app.UseSwagger();
app.UseSwaggerUI();

app.Run();
