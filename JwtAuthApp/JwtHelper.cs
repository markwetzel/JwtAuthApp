using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using Microsoft.IdentityModel.Tokens;

namespace JwtAuthApp;

public static class JwtHelper
{
    private const string SecretKey = "pGMiSLLGjzkYgjZ1yWzgbTCckI7qzGljMy2UFXoextY=";
    private static readonly SymmetricSecurityKey SigningKey = new(Encoding.UTF8.GetBytes(SecretKey));

    public static string GenerateToken(string username, string role)
    {
        var claims = new[]
        {
            new Claim(JwtRegisteredClaimNames.Sub, username),
            new Claim(ClaimTypes.Role, role), 
            new Claim(ClaimTypes.Name, username),
            new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
            new Claim(JwtRegisteredClaimNames.Iat, DateTimeOffset.UtcNow.ToUnixTimeSeconds().ToString(), ClaimValueTypes.Integer64),
            new Claim(JwtRegisteredClaimNames.Iss, "JwtAuthApp"),
            new Claim(JwtRegisteredClaimNames.Aud, "JwtAuthAppUsers")
        };
        
        var tokenDescriptor = new SecurityTokenDescriptor
        {
            Subject = new ClaimsIdentity(claims),
            Expires = DateTime.UtcNow.AddMinutes(30),
            SigningCredentials = new SigningCredentials(SigningKey, SecurityAlgorithms.HmacSha256)
        };

        var tokenHandler = new JwtSecurityTokenHandler();
        var token = tokenHandler.CreateToken(tokenDescriptor);

        return tokenHandler.WriteToken(token);
    }

    public static bool IsInRole(ClaimsPrincipal principal, string role)
    {
        var claim = principal?.FindFirst(ClaimTypes.Role);
        return claim?.Value == role; 
    }
    
    public static ClaimsPrincipal? ValidateToken(string token)
    {
        var tokenHandler = new JwtSecurityTokenHandler();

        var validationParameters = new TokenValidationParameters
        {
            ValidateIssuer = true,
            ValidateAudience = true,
            ValidateLifetime = true,
            ValidateIssuerSigningKey = true,
            IssuerSigningKey = SigningKey,
            ClockSkew = TimeSpan.Zero,
            ValidIssuer = "JwtAuthApp",
            ValidAudience = "JwtAuthAppUsers"
        };

        try
        {
            var principal = tokenHandler.ValidateToken(token, validationParameters, out _);
            return principal;
        }
        catch (Exception)
        {
            // Token validation failure 
            return null;
        }
    }
}