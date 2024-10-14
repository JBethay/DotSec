public class UserUnsecure
{
    public int Id { get; set; } 
    public string Username { get; set; }
    public string Password { get; set; }
}

public class User
{
    public Guid Id { get; set; } 
    public string Username { get; set; }
    public string PasswordHash { get; set; }
    public string Salt { get; set; }
}
