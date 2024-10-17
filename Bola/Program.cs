using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Identity;
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

builder.Services.AddAuthorization();

var app = builder.Build();

using (var scope = app.Services.CreateScope())
{
    var db = scope.ServiceProvider.GetRequiredService<MyDbContext>();
    var userManager = scope.ServiceProvider.GetRequiredService<UserManager<User>>();
    db.Database.EnsureCreated();
    await MyDbContext.SeedDatabase(db, userManager);
}

app.UseAuthentication();
app.UseAuthorization();

app.MapPost("/api/unsecure/details", async (UserUnsecure user, MyDbContext db) =>
{
    try
    {
        var foundUser = await db.UsersUnsecure.FirstOrDefaultAsync(_ => _.Id == user.Id);

        if (foundUser != null)
        {
            return Results.Ok(new { username = foundUser.Email });
        }
        else
        {
            return Results.Unauthorized();
        }
    }
    catch
    {
        return Results.Problem(statusCode: 500);
    }
}).WithName("unsecure").WithOpenApi();

//Note: you should never ever have something like this in a real app, I am only adding it so you can easily get the Guids. 
app.MapGet("/api/dangerous/getallusers", async (MyDbContext db) =>
{
    try
    {
        var users = await db.Users.ToListAsync();

        return Results.Ok(users.Select(_ => _.UserId).ToList());
    }
    catch
    {
        return Results.Problem(statusCode: 500);
    }
}).WithName("get all user ids [dangerous]").WithOpenApi();

app.MapPost("/api/details", async (User user, MyDbContext db) =>
{
    try
    {
        var foundUser = await db.Users.FirstOrDefaultAsync(_ => _.UserId == user.UserId);

        if (foundUser != null)
        {
            return Results.Ok(new { username = foundUser.Email });
        }
        else
        {
            return Results.Unauthorized();
        }
    }
    catch
    {
        return Results.Problem(statusCode: 500);
    }
}).WithName("more secure").WithOpenApi();

app.MapPost("/api/secure/details", async (User user, MyDbContext db, HttpContext httpContext) =>
{
    try
    {
        var foundUser = await db.Users.FirstOrDefaultAsync(_ => _.UserId == user.UserId);

        if (foundUser != null)
        {
            var emailClaim = httpContext.User.FindFirst(ClaimTypes.Email);
            if(foundUser.Email != emailClaim.Value) {
                return Results.Unauthorized();
            }

            return Results.Ok(new { username = foundUser.Email });
        }
        else
        {
            return Results.Unauthorized();
        }
    }
    catch
    {
        return Results.Problem(statusCode: 500);
    }
}).RequireAuthorization().WithName("most secure").WithOpenApi();

app.MapPost("/token", async (UserManager<User> userManager, SignInManager<User> signInManager, LoginModel loginModel) =>
{
    //Note, this is a very very simple implementation that could be hardened significantly
    var user = await userManager.FindByEmailAsync(loginModel.Email);
    var result = await signInManager.PasswordSignInAsync(loginModel.Email, loginModel.Password, isPersistent: false, lockoutOnFailure: false);
    if (result.Succeeded)
    {
        var claims = new[]
        {
            new Claim(JwtRegisteredClaimNames.Sub, loginModel.Email),
            new Claim(JwtRegisteredClaimNames.Email, loginModel.Email),
        };
    
        var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes("MySuperSuperSuperSuperSuperSecretKeyValue"));
        var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);
    
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