using System.Security.Cryptography;
using System.Text;

//Simple password hashing tool.
public static class PasswordHasher
{
    private const int SaltSize = 16;
    private const int KeySize = 64;
    private const int Iterations = 10000;
    private static readonly HashAlgorithmName s_hashAlgorithm = HashAlgorithmName.SHA512;

    public static (string hash, string salt) HashPassword(string password)
    {
        var salt = RandomNumberGenerator.GetBytes(SaltSize);
        var hash = Rfc2898DeriveBytes.Pbkdf2(
            Encoding.UTF8.GetBytes(password),
            salt,
            Iterations,
            s_hashAlgorithm,
            KeySize);
        return (Convert.ToHexString(hash), Convert.ToHexString(salt));
    }

    public static bool VerifyPassword(string password, string hash, string salt)
    {
        var hashToCompare = Rfc2898DeriveBytes.Pbkdf2(password, Convert.FromHexString(salt), Iterations, s_hashAlgorithm, KeySize);
        return CryptographicOperations.FixedTimeEquals(hashToCompare, Convert.FromHexString(hash));
    }
}