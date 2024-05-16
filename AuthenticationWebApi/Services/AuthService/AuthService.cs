using AuthenticationWebApi.Data;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Net;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;

namespace AuthenticationWebApi.Services.AuthService
{
    public class AuthService : IAuthService
    {
        private readonly DataContext _context;
        private readonly IConfiguration _configuration;
        private readonly IHttpContextAccessor _httpContextAccessor;

        public AuthService(DataContext context, IConfiguration configuration, IHttpContextAccessor httpContextAccessor)
        {
            _context = context;
            _configuration = configuration;
            _httpContextAccessor = httpContextAccessor;
        }

        public async Task<AuthResponseDto> Login(UserDto request)
        {
            var user = await _context.Users.FirstOrDefaultAsync(u => u.UserName == request.UserName);
            if (user == null)
            {
                return new AuthResponseDto { Message = "User Not Found" };
            }
            if (!VerifyPasswordHash(request.Password, user.PasswordHash, user.PassworSalt))
            {
                return new AuthResponseDto { Message = "Wrong Password" };
            }
            string token = CreateToken(user);
            var refreshToken = CreateRefreshToken();
            SetRefreshToken(refreshToken, user);

            //set token vào cookie
            var cookieOptions = new CookieOptions
            {
                HttpOnly = true,
                Expires = DateTime.UtcNow.AddMinutes(1),
                SameSite = SameSiteMode.None,
                Secure = true,
                //Domain = "localhost:3001"
            };
            _httpContextAccessor?.HttpContext?.Response.Cookies
                .Append("token", token, cookieOptions);

            return new AuthResponseDto
            {
                IsSuccess = true,
                Token = token,
                RefreshToken = refreshToken.Token,
                TokenExpires = DateTime.UtcNow.AddMinutes(1),
                RefreshTokenExpires = refreshToken.Expires
            };
        }

        public async Task<User> RegisterUser(UserDto request)
        {
            CreatePasswordHash(request.Password, out byte[] passwordHash, out byte[] passwordsalt);
            var user = new User
            {
                UserName = request.UserName,
                PasswordHash = passwordHash,
                PassworSalt = passwordsalt
            };

            _context.Users.Add(user);
            await _context.SaveChangesAsync();

            return user;
        }

        public async Task<AuthResponseDto> RefreshToken()
        {
            var refreshToken = _httpContextAccessor?.HttpContext?.Request.Cookies["refreshToken"];
            //string refreshToken = _httpContextAccessor.HttpContext.Request.Headers["cookieCustom"];
            var user = await _context.Users.FirstOrDefaultAsync(u => u.RefreshToken == refreshToken);
            if (user == null)
            {
                return new AuthResponseDto { Message = "Invalid Refresh Token" };
            }
            else if (user.TokenExpires < DateTime.UtcNow)
            {
                return new AuthResponseDto { Message = "Token Expired" };
            }
            string token = CreateToken(user);
            var newRefreshToken = CreateRefreshToken();
            SetRefreshToken(newRefreshToken, user);

            //set token vào cookie
            var cookieOptions = new CookieOptions
            {
                HttpOnly = true,
                Expires = DateTime.UtcNow.AddMinutes(1),
                SameSite = SameSiteMode.None,
                Secure = true,
                //Domain = "localhost:3001"
            };
            _httpContextAccessor?.HttpContext?.Response.Cookies
                .Append("token", token, cookieOptions);

            return new AuthResponseDto
            {
                IsSuccess = true,
                Token = token,
                RefreshToken = newRefreshToken.Token,
                RefreshTokenExpires = newRefreshToken.Expires,
                TokenExpires = DateTime.UtcNow.AddMinutes(1),
            };
        }

        private bool VerifyPasswordHash(string password, byte[] passwordHash, byte[] passwordSalt)
        {
            using (var hmac = new HMACSHA512(passwordSalt))
            {
                var computedHash = hmac.ComputeHash(System.Text.Encoding.UTF8.GetBytes(password));
                return computedHash.SequenceEqual(passwordHash);
            }
        }

        private void CreatePasswordHash(string password, out byte[] passwordHash, out byte[] passwordSalt)
        {
            using (var hmac = new HMACSHA512())
            {
                passwordSalt = hmac.Key;
                passwordHash = hmac.ComputeHash(System.Text.Encoding.UTF8.GetBytes(password));
            }
        }

        public string CreateToken(User user)
        {
            List<Claim> claims = new List<Claim>
            {
                new Claim(ClaimTypes.NameIdentifier, user.Id.ToString()),
                new Claim(ClaimTypes.Name, user.UserName),
                new Claim(ClaimTypes.Role, user.Role)
            };
            var key = new SymmetricSecurityKey(System.Text.Encoding.UTF8.GetBytes(
                    _configuration.GetSection("AppSettings:Token").Value
                ));
            var credential = new SigningCredentials(key, SecurityAlgorithms.HmacSha512Signature);
            var token = new JwtSecurityToken(
                    claims: claims,
                    expires: DateTime.UtcNow.AddMinutes(1),
                    signingCredentials: credential
                );
            var jwt = new JwtSecurityTokenHandler().WriteToken(token);
            return jwt;
        }

        public RefreshToken CreateRefreshToken()
        {
            var refreshToken = new RefreshToken
            {
                Token = Convert.ToBase64String(RandomNumberGenerator.GetBytes(64)),
                Expires = DateTime.UtcNow.AddDays(1),
                Created = DateTime.UtcNow
            };
            return refreshToken;
        }

        public async Task SetRefreshToken(RefreshToken refreshToken, User user)
        {
            var cookieOptions = new CookieOptions
            {
                HttpOnly = true,
                Expires = refreshToken.Expires,
                SameSite = SameSiteMode.None,
                Secure = true,
                //Domain = "localhost:3001"
            };
            _httpContextAccessor?.HttpContext?.Response.Cookies
                .Append("refreshToken", refreshToken.Token, cookieOptions);

            user.RefreshToken = refreshToken.Token;
            user.TokenCreated = refreshToken.Created;
            user.TokenExpires = refreshToken.Expires;
            await _context.SaveChangesAsync();
        }

        protected string GetNameFromToken(string token)
        {
            string secret = "dcm123abcdcm123abc";
            var key = Encoding.ASCII.GetBytes(secret);
            var handler = new JwtSecurityTokenHandler();
            var validations = new TokenValidationParameters
            {
                ValidateIssuerSigningKey = true,
                IssuerSigningKey = new SymmetricSecurityKey(key),
                ValidateIssuer = false,
                ValidateAudience = false
            };
            var claims = handler.ValidateToken(token, validations, out var tokenSecure);
            return claims.Identity.Name;
        }
        public async Task<bool> ValidateRefreshToken(string refreshToken)
        {
            // Lấy thông tin user từ database
            var user = await _context.Users.FirstOrDefaultAsync(u => u.RefreshToken == refreshToken);

            // Kiểm tra xem refresh token có hợp lệ hay không
            if (user == null) { return  false; }

            // Kiểm tra xem refresh token đã hết hạn hay chưa
            if (DateTime.UtcNow > user.TokenExpires)
            {
                return false;
            }

            // Refresh token hợp lệ
            return true;
        }
        public async Task<User> GetUserFromRefreshToken(string refreshToken)
        {
            var user = await _context.Users.FirstOrDefaultAsync(u => u.RefreshToken == refreshToken);
            if(user == null) { return null; }
            return user;
        }

    }
}
