using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;

public class MyDbContext : IdentityDbContext<User>
{
    public MyDbContext(DbContextOptions<MyDbContext> options) : base(options) { }

    public DbSet<UserUnsecure> UsersUnsecure { get; set; }

    public static async Task SeedDatabase(MyDbContext db, UserManager<User> userManager)
    {
        if (!db.UsersUnsecure.Any())
        {
            db.UsersUnsecure.AddRange(new List<UserUnsecure>
            {
                new() { Email = "normal@normal.com", Id = 1 },
                new() { Email = "admin@admin.com", Id = 2 },
                new() { Email = "super@admin.com", Id = 3 },

            });
            db.SaveChanges();
        }

        _ = await userManager.CreateAsync(new() { UserId = Guid.NewGuid(), Email = "normal@normal.com", UserName = "normal@normal.com"  }, "Password1!"); // Use a strong password policy and never hard code user creation in a real app
        _ = await userManager.CreateAsync(new() { UserId = Guid.NewGuid(), Email = "admin@admin.com", UserName = "admin@admin.com" }, "Password1!"); // Use a strong password policy nd never hard code user creation in a real app
        _ = await userManager.CreateAsync(new() { UserId = Guid.NewGuid(), Email = "super@admin.com", UserName = "super@admin.com"  }, "Password1!"); // Use a strong password policy and never hard code user creation in a real app
    }
}

public class UserUnsecure
{
    public int Id { get; set; } 
    public string Email { get; set; }
}

public class User : IdentityUser
{
    public Guid UserId { get; set; }
}

public class LoginModel {
    public string Email { get; set; }
    public string Password { get; set; }
}
