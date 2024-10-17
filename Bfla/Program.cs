using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using Microsoft.OpenApi.Models;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddDbContext<MyDbContext>(options =>
    options.UseInMemoryDatabase("MyInMemoryDb"));

builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen(c =>
{
    c.SwaggerDoc("v1", new OpenApiInfo { Title = "BOLA API", Version = "v1" });
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

using (var scope = app.Services.CreateScope())
{
    var db = scope.ServiceProvider.GetRequiredService<MyDbContext>();
    var userManager = scope.ServiceProvider.GetRequiredService<UserManager<User>>();
    var roleManager = scope.ServiceProvider.GetRequiredService<RoleManager<IdentityRole>>();
    db.Database.EnsureCreated();
    await MyDbContext.SeedDatabase(db, userManager, roleManager);
}

app.UseAuthentication();
app.UseAuthorization();

app.MapDelete("/api/insecure/delete", async ([FromBody]UserDetails user, MyDbContext db) =>
{
    try
    {
        var foundUser = await db.Users.FirstOrDefaultAsync(u => u.UserName == user.UserName);

        if (foundUser != null)
        {
            db.Users.Remove(foundUser);
            await db.SaveChangesAsync();
            return Results.Ok($"Deleted {user.UserName}");
        }
        else
        {
            return Results.BadRequest();
        }
    }
    catch
    {
        return Results.Problem(statusCode: 500);
    }
}).WithName("insecure").WithOpenApi();


app.MapDelete("/api/secure/delete", async ([FromBody]UserDetails user, MyDbContext db, HttpContext httpContext) =>
{
    try
    {
        var foundUser = await db.Users.FirstOrDefaultAsync(u => u.UserName == user.UserName);

        if (foundUser != null)
        {
            db.Users.Remove(foundUser);
            await db.SaveChangesAsync();
            return Results.Ok($"Deleted {user.UserName}");
        }
        else
        {
            return Results.BadRequest();
        }
    }
    catch
    {
        return Results.Problem(statusCode: 500);
    }
}).RequireAuthorization(options => options.RequireRole("Admin"))
.WithName("secure").WithOpenApi();

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
        
        var roles = await userManager.GetRolesAsync(user);
        foreach (var role in roles)
        {
            claims.Add(new Claim(ClaimTypes.Role, role));
        }

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
