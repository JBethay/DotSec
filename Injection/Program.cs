using Microsoft.EntityFrameworkCore;
var builder = WebApplication.CreateBuilder(args);

var dbPath = "users.db";
builder.Services.AddDbContext<MyDbContext>(options =>
    options.UseSqlite($"Data Source={dbPath}"));

builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();
var app = builder.Build();

using (var scope = app.Services.CreateScope())
{
    var db = scope.ServiceProvider.GetRequiredService<MyDbContext>();
    db.Database.EnsureCreated();
    MyDbContext.SeedDatabase(db);
}

app.MapPost("/api/unsecure/login", async (UserUnsecure user, MyDbContext db) =>
{
    try
    {
        var query = $"SELECT * FROM UsersUnsecure WHERE Username = '{user.Username}' AND Password = '{user.Password}'";
        var foundUser = await db.UsersUnsecure.FromSqlRaw(query).FirstOrDefaultAsync();

        if (foundUser != null)
        {
            return Results.Ok(new { username = foundUser.Username });
        }
        else
        {
            return Results.Unauthorized();
        }
    }
    catch(Exception ex)
    {
        return Results.Problem(statusCode: 500);
    }
}).WithName("unsecure").WithOpenApi();


app.MapPost("/api/login", async (UserUnsecure user, MyDbContext db) =>
{
    try
    {
        var userName = new Microsoft.Data.Sqlite.SqliteParameter("userName", user.Username);
        var foundUser = await db.Users.FromSqlRaw("SELECT * FROM Users WHERE Username = @userName", userName).FirstOrDefaultAsync();
        var AlsoWorks = await db.Users.FromSql($"SELECT * FROM Users WHERE Username = {user.Username}").FirstOrDefaultAsync();

        if (foundUser != null)
        {
            if(!PasswordHasher.VerifyPassword(user.Password, foundUser.PasswordHash, foundUser.Salt)) {
                return Results.Unauthorized();
            }

            return Results.Ok(new { username = foundUser.Username });
        }
        else
        {
            return Results.Unauthorized();
        }
    }
    catch(Exception ex)
    {
        return Results.Problem(statusCode: 500);
    }
}).WithName("more_secure").WithOpenApi();

app.UseSwagger();
app.UseSwaggerUI();

app.Lifetime.ApplicationStopping.Register(() =>
{
    if (File.Exists(dbPath))
    {
        File.Delete(dbPath);
    }
    if (File.Exists($"{dbPath}-shm"))
    {
        File.Delete($"{dbPath}-shm");
    }
    if (File.Exists($"{dbPath}-wal"))
    {
        File.Delete($"{dbPath}-wal");
    }
});

app.Run();

/* 
{
  "username": "bad' OR '1'='1",
  "password": "bad' OR '1'='1"
}
*/