using Microsoft.EntityFrameworkCore;

public class MyDbContext : DbContext
{
    public MyDbContext(DbContextOptions<MyDbContext> options) : base(options) { }

    public DbSet<UserUnsecure> UsersUnsecure { get; set; }

    public DbSet<User> Users { get; set; }

    public static void SeedDatabase(MyDbContext db)
    {
        if (!db.UsersUnsecure.Any())
        {
            db.UsersUnsecure.AddRange(new List<UserUnsecure>
            {
                new() { Username = "admin", Password = "admin" },
            });
            db.SaveChanges();
        }
    
        if (!db.Users.Any())
        {
            var (passwordHash, salt) = PasswordHasher.HashPassword("c&BJZ6rwQA2ohuTU");
    
            db.Users.AddRange(new List<User>
            {
                new() { Username = "admin", PasswordHash = passwordHash, Salt = salt },
            });
            db.SaveChanges();
        }
    }
}