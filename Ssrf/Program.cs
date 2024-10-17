var builder = WebApplication.CreateBuilder(args);

builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();
builder.Services.AddHttpClient();
builder.Services.AddHttpClient("SecureHttpClient").ConfigurePrimaryHttpMessageHandler(() => new HttpClientHandler{ AllowAutoRedirect = false });

var app = builder.Build();

app.MapGet("/api/inband", async (string uri, HttpClient httpClient) => 
{
    try
    {
        var result = await httpClient.GetAsync(uri);

        if(result.IsSuccessStatusCode) { 
            return Results.Ok(await result.Content.ReadAsStringAsync());
        }

        return Results.Problem(statusCode: 500);
    }
    catch
    {
        return Results.Problem(statusCode: 500);
    }
}).WithName("inband").WithOpenApi();

app.MapGet("/api/outofbad", async (string uri, HttpClient httpClient) => 
{
    try
    {
        var result = await httpClient.GetAsync(uri);

        if(result.IsSuccessStatusCode) { 
            return Results.Ok("Request was successful");
        }
        
        return Results.Problem(statusCode: 500);
    }
    catch
    {
        return Results.Problem(statusCode: 500);
    }
}).WithName("blind").WithOpenApi();

app.MapGet("/api/secured", async (string uri, IHttpClientFactory httpClientFactory) => 
{
    try
    {
        var allowedSchemes = new HashSet<string>() { "https" };
        var allowedDomains = new HashSet<string>() { "www.google.com" };
        var allowedPorts = new HashSet<int>() { 443 };

        var requestUri = new Uri(uri);
        if (!allowedSchemes.Contains(requestUri.Scheme) || 
            !allowedDomains.Contains(requestUri.Host) || 
            !allowedPorts.Contains(requestUri.Port)) 
        {
            return Results.BadRequest();
        }

        var httpClient = httpClientFactory.CreateClient("SecureHttpClient");
        var result = await httpClient.GetAsync(requestUri);

        if (result.IsSuccessStatusCode) 
        { 
            return Results.Ok("Request was successful");
        }
        
        return Results.Problem(statusCode: 500);
    }
    catch
    {
        return Results.Problem(statusCode: 500);
    }
}).WithName("secure").WithOpenApi();


app.UseSwagger();
app.UseSwaggerUI();

app.Run();
