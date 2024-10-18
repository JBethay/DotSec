using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using Asp.Versioning;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using Microsoft.OpenApi.Models;

var builder = WebApplication.CreateBuilder(args);

//A better way to handle api versioning
builder.Services.AddApiVersioning(options => {
    options.DefaultApiVersion = new(2);
    options.AssumeDefaultVersionWhenUnspecified = true;
    options.ReportApiVersions = false; //Don't report versions
    options.UnsupportedApiVersionStatusCode = 400;
    options.ApiVersionReader = ApiVersionReader.Combine(
        new HeaderApiVersionReader("api-x-version"),
        new QueryStringApiVersionReader("api-version")
    );
}).AddApiExplorer(config => {
    config.GroupNameFormat = "'v'V";
    config.SubstituteApiVersionInUrl = true;
});

builder.Services.AddDbContext<MyDbContext>(options =>
    options.UseInMemoryDatabase("MyInMemoryDb"));

builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen(c =>
{
    c.SwaggerDoc("v1", new OpenApiInfo { Title = "IIM API", Version = "v1" });
    var securityScheme = new OpenApiSecurityScheme
    {
        Name = "Authorization",
        Description = "JWT Authorization header using the Bearer scheme",
        In = ParameterLocation.Header,
        Type = SecuritySchemeType.Http,
        Scheme = "Bearer",
        BearerFormat = "JWT"
    };
    c.AddSecurityDefinition("Token", securityScheme);
    c.AddSecurityRequirement(new OpenApiSecurityRequirement
    {
        {
            new OpenApiSecurityScheme
            {
                Reference = new OpenApiReference
                {
                    Type = ReferenceType.SecurityScheme,
                    Id = "Token"
                }
            },
            Array.Empty<string>()
        }
    });
});

builder.Services.AddIdentity<User, IdentityRole>()
    .AddEntityFrameworkStores<MyDbContext>()
    .AddDefaultTokenProviders();

var key = "MySuperSuperSuperSuperSuperSecretKeyValue"; // Use a key from KV or dotnet user secrets
builder.Services.AddAuthentication(options =>
{
    options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
    options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
})
.AddJwtBearer(options =>
{
    options.TokenValidationParameters = new TokenValidationParameters
    {
        ValidateIssuerSigningKey = false, // YOU SHOULD VALIDATE A SIGNING KEY
        IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(key)),
        ValidateIssuer = false, // YOU SHOULD VALIDATE A PRODUCTION ISSUER
        ValidateAudience = false // YOU SHOULD VALIDATE A PRODUCTION AUDIENCE
    };
});

builder.Services.AddAuthorization(options => {
    options.AddPolicy("AdminAccess", policy =>
    policy.RequireClaim("AdminAccess", "true"));
});

var app = builder.Build();

//Better way to handle api versions
var apiVersionSet = app.NewApiVersionSet()
    .HasApiVersion(new(2))
    .HasDeprecatedApiVersion(new(1))
    .Build();

using (var scope = app.Services.CreateScope())
{
    var db = scope.ServiceProvider.GetRequiredService<MyDbContext>();
    var userManager = scope.ServiceProvider.GetRequiredService<UserManager<User>>();
    db.Database.EnsureCreated();
    await MyDbContext.SeedDatabase(db, userManager);
}

app.UseAuthentication();
app.UseAuthorization();

app.MapGet("/api/v1/details", async (MyDbContext db) =>
{
    try
    {
        var users = await db.Users.Select(u => new UserFullDetails { UserName = u.UserName, IsAdmin = u.IsAdmin }).ToListAsync();
        return Results.Ok(users);
    }
    catch
    {
        return Results.Problem(statusCode: 500);
    }
}).WithName("v1").WithOpenApi();

app.MapGet("/api/v2/details", async (MyDbContext db, HttpContext httpContext) =>
{
    try
    {
        var users = await db.Users.Select(u => new UserFullDetails { UserName = u.UserName, IsAdmin = u.IsAdmin }).ToListAsync();
        return Results.Ok(users);
    }
    catch
    {
        return Results.Problem(statusCode: 500);
    }
}).RequireAuthorization(options => options.RequireClaim("AdminAccess"))
.WithName("v2").WithOpenApi();

//Use This Instead
app.MapGet("/api/details", () => Results.StatusCode(406)).WithApiVersionSet(apiVersionSet).MapToApiVersion(1);

app.MapGet("/api/details", async (MyDbContext db, HttpContext httpContext) =>
{
    try
    {
        var users = await db.Users.Select(u => new UserFullDetails { UserName = u.UserName, IsAdmin = u.IsAdmin }).ToListAsync();
        return Results.Ok(users);
    }
    catch
    {
        return Results.Problem(statusCode: 500);
    }
}).RequireAuthorization(options => options.RequireClaim("AdminAccess"))
.WithApiVersionSet(apiVersionSet).MapToApiVersion(2);

app.MapPost("/token", async (UserManager<User> userManager, SignInManager<User> signInManager, LoginModel loginModel) =>
{
    //Note, this is a very very simple implementation that could be hardened significantly
    var user = await userManager.FindByEmailAsync(loginModel.Email);
    var result = await signInManager.PasswordSignInAsync(loginModel.Email, loginModel.Password, isPersistent: false, lockoutOnFailure: false);
    if (result.Succeeded && user != null)
    {   
        var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes("MySuperSuperSuperSuperSuperSecretKeyValue"));
        var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);
    
        // A Note On Claims, NEVER add sensitive information to a JWT, you can easily go to something like https://jwt.io/ and decode the token and see all the claims at any time.
        // Make sure you hve a strong signing key as an issuer and make sure you validate claims.
        var claims = await userManager.GetClaimsAsync(user);
        claims.Add(new Claim(JwtRegisteredClaimNames.Sub, user.UserName)); 
        claims.Add(new Claim(JwtRegisteredClaimNames.Email, user.Email));

        var token = new JwtSecurityToken(
            issuer: null,
            audience: null,
            claims: claims,
            expires: DateTime.Now.AddMinutes(30),
            signingCredentials: creds);
    
            return Results.Ok(new { Token = new JwtSecurityTokenHandler().WriteToken(token) });
    }
    return Results.BadRequest();
}).AllowAnonymous().WithName("token").WithOpenApi();

app.UseSwagger();
app.UseSwaggerUI();

app.Run();
