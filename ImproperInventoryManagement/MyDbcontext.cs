using System.Security.Claims;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;

public class MyDbContext : IdentityDbContext<User>
{
    public MyDbContext(DbContextOptions<MyDbContext> options) : base(options) { }

    public static async Task SeedDatabase(MyDbContext db, UserManager<User> userManager)
    {
        var normalUser = new User() { UserId = Guid.NewGuid(), Email = "normal@normal.com", UserName = "normal@normal.com"  };
        var adminUser = new User() { UserId = Guid.NewGuid(), Email = "admin@admin.com", UserName = "admin@admin.com", IsAdmin = true };
        _ = await userManager.CreateAsync(normalUser, "Password1!"); // Use a strong password policy and never hard code user creation in a real app
        _ = await userManager.CreateAsync(adminUser, "Password1!"); // Use a strong password policy nd never hard code user creation in a real app
        _ = await userManager.AddClaimAsync(adminUser, new Claim("AdminAccess", "true"));
    }
}

public class User : IdentityUser
{
    public Guid UserId { get; set; }
    public bool IsAdmin { get; set; }
}

public record UserDetails {
    public string UserName { get; set; }
}

public record UserFullDetails {
    public string UserName { get; set; }
    public bool IsAdmin { get; set; }
}

public record LoginModel {
    public string Email { get; set; }
    public string Password { get; set; }
}
