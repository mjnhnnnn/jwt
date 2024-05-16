
namespace AuthenticationWebApi.Services.AuthService
{
    public interface IAuthService
    {
        Task<User> RegisterUser(UserDto request);
        Task<AuthResponseDto> Login(UserDto request);
        Task<AuthResponseDto> RefreshToken();
        Task<bool> ValidateRefreshToken(string refreshToken);
        Task<User> GetUserFromRefreshToken(string refreshToken);
        public string CreateToken(User user);
        public RefreshToken CreateRefreshToken();
        Task SetRefreshToken(RefreshToken refreshToken, User user);
    }
}
