using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Configuration;
using System.Net;

namespace AuthenticationWebApi.RefreshTokenMiddleware
{
    public class RefreshTokenMiddleware
    {
        private readonly RequestDelegate _next;
        private readonly IConfiguration _configuration;

        public RefreshTokenMiddleware(RequestDelegate next, IConfiguration configuration)
        {
            _next = next;
            _configuration = configuration;
        }

        public async Task Invoke(HttpContext context, IAuthService _authService)
        {
            var ignoredPaths = new List<string> { "/api/Auth/refresh-token", "/api/Auth/login", "/api/Auth/register" };
            if (!ignoredPaths.Contains(context.Request.Path.Value))
            {
                // Lấy refresh token từ cookie hoặc header của request
                string refreshToken = context.Request.Cookies["refreshToken"] ?? context.Request.Headers["Authorization"].ToString().Replace("Bearer ", "");

                string token = context.Request.Cookies["token"];

                if (token == null)
                {
                    if (!string.IsNullOrEmpty(refreshToken))
                    {
                        bool isValid = await _authService.ValidateRefreshToken(refreshToken);
                        // Kiểm tra nếu refresh token tồn tại và hợp lệ
                        if (isValid)
                        {
                            // Lấy thông tin user từ refresh token
                            var user = await _authService.GetUserFromRefreshToken(refreshToken);

                            if (user != null)
                            {
                                // Tạo mới token và refresh token mới
                                var newToken = _authService.CreateToken(user);
                                var newRefreshToken = _authService.CreateRefreshToken();

                                // Set lại refresh token mới vào cookie và cập nhật thông tin user trong database
                                _authService.SetRefreshToken(newRefreshToken, user);


                                context.Response.Cookies.Append("refreshToken", newRefreshToken.Token, new CookieOptions
                                {
                                    HttpOnly = true,
                                    Expires = newRefreshToken.Expires,
                                    SameSite = SameSiteMode.None,
                                    Secure = true
                                });
                                context.Response.Cookies.Append("token", newToken, new CookieOptions
                                {
                                    HttpOnly = true,
                                    Expires = DateTime.UtcNow.AddMinutes(1),
                                    SameSite = SameSiteMode.None,
                                    Secure = true
                                });
                                // Gắn token và refresh token mới vào header Authorization của response
                                context.Request.Headers.Add("Authorization", "Bearer " + newToken);

                            }
                            else
                            {
                                return;
                            }

                        }
                        else
                        {
                            context.Response.StatusCode = (int)HttpStatusCode.Unauthorized;
                            await context.Response.WriteAsync("Invalid refresh token");
                            return;
                        }
                    }
                }
                else
                {
                    context.Request.Headers.Add("Authorization", "Bearer " + token);
                }
            }            
            // Gọi tiếp middleware kế tiếp
            await _next(context);
        }
    }
}

