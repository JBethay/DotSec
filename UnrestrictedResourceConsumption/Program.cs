using System.Threading.RateLimiting;
using Microsoft.AspNetCore.RateLimiting;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddRateLimiter(_ => _
    .AddSlidingWindowLimiter(policyName: "slidingWindow", options =>
    {
        options.PermitLimit = 4;
        options.Window = TimeSpan.FromMicroseconds(120000);
        options.SegmentsPerWindow = 25;
        options.QueueProcessingOrder = QueueProcessingOrder.OldestFirst;
        options.QueueLimit = 5;
    }));

var app = builder.Build();

app.UseRateLimiter();

const int EndpointTimeout = 15000;

app.MapGet("/", async (CancellationToken cancellationToken) => await SomeTask(cancellationToken))
    .WithRequestTimeout(TimeSpan.FromMilliseconds(EndpointTimeout))
    .RequireRateLimiting("slidingWindow");

static async Task<string> SomeTask(CancellationToken Token) { 
    await Task.Delay(10000, Token); 
    return "Hello World"!;
}

app.Run();
