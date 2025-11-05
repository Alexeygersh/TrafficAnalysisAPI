using BCrypt.Net;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using TrafficAnalysisAPI.Data;
using TrafficAnalysisAPI.Models;
using TrafficAnalysisAPI.Services.Interfaces;

namespace TrafficAnalysisAPI.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthController : ControllerBase
    {
        private readonly IAuthService _authService;
        private readonly IConfiguration _configuration;
        private readonly ILogger<AuthController> _logger;

        public AuthController(
            IAuthService authService,
            IConfiguration configuration,
            ILogger<AuthController> logger)
        {
            _authService = authService;
            _configuration = configuration;
            _logger = logger;
        }

        // запрос авторизации
        public class LoginRequest
        {
            public string Username { get; set; }
            public string Password { get; set; }
        }

        // ответ с токеном
        public class LoginResponse
        {
            public string Token { get; set; }
            public string Username { get; set; }
            public string Role { get; set; }
        }

        // регистрация
        public class RegisterRequest
        {
            public string Username { get; set; }
            public string Password { get; set; }
            public string Role { get; set; } // "Admin" или "Analyst"
        }

        // Авторизация пользователя
        // ---> JWT
        [HttpPost("login")]
        [ProducesResponseType(StatusCodes.Status200OK)]
        [ProducesResponseType(StatusCodes.Status401Unauthorized)]
        public async Task<ActionResult<LoginResponse>> Login([FromBody] LoginRequest request)
        {
            // Валидация входных данных
            if (string.IsNullOrWhiteSpace(request.Username) || string.IsNullOrWhiteSpace(request.Password))
            {
                _logger.LogWarning("Login attempt with empty credentials");
                return Unauthorized(new { message = "Логин и пароль обязательны" });
            }

            try
            {
                // Поиск пользователя через сервис
                var user = await _authService.GetUserByUsernameAsync(request.Username);

                if (user == null)
                {
                    _logger.LogWarning($"Login attempt for non-existent user: {request.Username}");
                    return Unauthorized(new { message = "Неверный логин или пароль" });
                }

                // Проверка пароля через сервис
                bool isPasswordValid = _authService.VerifyPassword(request.Password, user.PasswordHash);

                if (!isPasswordValid)
                {
                    _logger.LogWarning($"Invalid password for user: {request.Username}");
                    return Unauthorized(new { message = "Неверный логин или пароль" });
                }

                // Генерация JWT токена
                var token = GenerateJwtToken(user);

                _logger.LogInformation($"User {user.Username} logged in successfully");

                return Ok(new LoginResponse
                {
                    Token = token,
                    Username = user.Username,
                    Role = user.Role
                });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error during login");
                return StatusCode(500, new { message = "Внутренняя ошибка сервера" });
            }
        }

        // Регистрация нового пользователя (только для админов)
        [HttpPost("register")]
        [ProducesResponseType(StatusCodes.Status201Created)]
        [ProducesResponseType(StatusCodes.Status400BadRequest)]
        public async Task<ActionResult<LoginResponse>> Register([FromBody] RegisterRequest request)
        {
            // Валидация
            if (string.IsNullOrWhiteSpace(request.Username) ||
                string.IsNullOrWhiteSpace(request.Password))
            {
                return BadRequest(new { message = "Логин и пароль обязательны" });
            }

            if (request.Password.Length < 6)
            {
                return BadRequest(new { message = "Пароль должен быть минимум 6 символов" });
            }

            if (request.Role != "Admin" && request.Role != "Analyst")
            {
                return BadRequest(new { message = "Роль должна быть Admin или Analyst" });
            }

            try
            {
                // Проверка существования пользователя через сервис
                var userExists = await _authService.UserExistsAsync(request.Username);

                if (userExists)
                {
                    return BadRequest(new { message = "Пользователь с таким именем уже существует" });
                }

                // Создание нового пользователя через сервис
                var newUser = await _authService.CreateUserAsync(
                    request.Username,
                    request.Password,
                    request.Role);

                // Генерация токена для нового пользователя
                var token = GenerateJwtToken(newUser);

                return CreatedAtAction(
                    nameof(Login),
                    new LoginResponse
                    {
                        Token = token,
                        Username = newUser.Username,
                        Role = newUser.Role
                    });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error during registration");
                return StatusCode(500, new { message = "Ошибка при регистрации пользователя" });
            }
        }

        // Генерация JWT
        private string GenerateJwtToken(User user)
        {
            var jwtSettings = _configuration.GetSection("JwtSettings");
            var secretKey = jwtSettings["SecretKey"];
            var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(secretKey));
            var credentials = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

            var claims = new[]
            {
                new Claim(ClaimTypes.NameIdentifier, user.Id.ToString()),
                new Claim(ClaimTypes.Name, user.Username),
                new Claim(ClaimTypes.Role, user.Role),
                new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()) // Уникальный ID токена
            };

            var token = new JwtSecurityToken(
                issuer: jwtSettings["Issuer"],
                audience: jwtSettings["Audience"],
                claims: claims,
                expires: DateTime.UtcNow.AddDays(1),
                signingCredentials: credentials
            );

            return new JwtSecurityTokenHandler().WriteToken(token);
        }

        // Получить информацию о текущем пользователе
        [HttpGet("me")]
        [ProducesResponseType(StatusCodes.Status200OK)]
        [ProducesResponseType(StatusCodes.Status401Unauthorized)]
        public async Task<ActionResult<object>> GetCurrentUser()
        {
            // Получить ID пользователя из токена
            var userIdClaim = User.FindFirst(ClaimTypes.NameIdentifier);
            if (userIdClaim == null)
            {
                return Unauthorized(new { message = "Токен недействителен" });
            }

            var userId = int.Parse(userIdClaim.Value);
            var user = await _authService.GetUserByIdAsync(userId);

            if (user == null)
            {
                return NotFound(new { message = "Пользователь не найден" });
            }

            return Ok(new
            {
                user.Id,
                user.Username,
                user.Role,
                user.CreatedAt
            });
        }
    }
}