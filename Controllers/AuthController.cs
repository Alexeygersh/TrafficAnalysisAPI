using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using TrafficAnalysisAPI.Models;
using TrafficAnalysisAPI.Services.Interfaces;
using TrafficAnalysisAPI.DTOs.Auth;

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

        // Авторизация пользователя
        [HttpPost("login")]
        [ProducesResponseType(typeof(LoginResponseDto), StatusCodes.Status200OK)]
        [ProducesResponseType(StatusCodes.Status401Unauthorized)]
        public async Task<ActionResult<LoginResponseDto>> Login([FromBody] LoginRequestDTO request)
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

                return Ok(new LoginResponseDto
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
        [Authorize(Roles = "Admin")]
        [ProducesResponseType(typeof(LoginResponseDto), StatusCodes.Status201Created)]
        [ProducesResponseType(StatusCodes.Status400BadRequest)]
        [ProducesResponseType(StatusCodes.Status403Forbidden)]
        public async Task<ActionResult<LoginResponseDto>> Register([FromBody] RegisterRequestDto request)
        {
            // Валидация через DataAnnotations происходит автоматически
            if (!ModelState.IsValid)
            {
                return BadRequest(ModelState);
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

                _logger.LogInformation($"Admin {User.Identity?.Name} created new user: {newUser.Username}");

                // Генерация токена для нового пользователя
                var token = GenerateJwtToken(newUser);

                return CreatedAtAction(
                    nameof(GetCurrentUser),
                    new { id = newUser.Id },
                    new LoginResponseDto
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

        // Получить информацию о текущем пользователе
        [HttpGet("me")]
        [Authorize]
        [ProducesResponseType(typeof(UserDto), StatusCodes.Status200OK)]
        [ProducesResponseType(StatusCodes.Status401Unauthorized)]
        public async Task<ActionResult<UserDto>> GetCurrentUser()
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

            return Ok(new UserDto
            {
                Id = user.Id,
                Username = user.Username,
                Role = user.Role,
                CreatedAt = user.CreatedAt
            });
        }

        // Получить список всех пользователей (только для админов)
        [HttpGet("users")]
        [Authorize(Roles = "Admin")]
        [ProducesResponseType(typeof(IEnumerable<UserDto>), StatusCodes.Status200OK)]
        [ProducesResponseType(StatusCodes.Status403Forbidden)]
        public async Task<ActionResult<IEnumerable<UserDto>>> GetAllUsers()
        {
            try
            {
                var users = await _authService.GetAllUsersAsync();

                var userDtos = users.Select(u => new UserDto
                {
                    Id = u.Id,
                    Username = u.Username,
                    Role = u.Role,
                    CreatedAt = u.CreatedAt
                });

                return Ok(userDtos);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error getting all users");
                return StatusCode(500, new { message = "Ошибка при получении списка пользователей" });
            }
        }

        // Удалить пользователя (только для админов)
        [HttpDelete("users/{id}")]
        [Authorize(Roles = "Admin")]
        [ProducesResponseType(StatusCodes.Status204NoContent)]
        [ProducesResponseType(StatusCodes.Status404NotFound)]
        [ProducesResponseType(StatusCodes.Status403Forbidden)]
        public async Task<IActionResult> DeleteUser(int id)
        {
            try
            {
                var currentUserId = int.Parse(User.FindFirst(ClaimTypes.NameIdentifier)?.Value ?? "0");

                if (currentUserId == id)
                {
                    return BadRequest(new { message = "Нельзя удалить самого себя" });
                }

                var deleted = await _authService.DeleteUserAsync(id);

                if (!deleted)
                {
                    return NotFound(new { message = "Пользователь не найден" });
                }

                _logger.LogInformation($"Admin {User.Identity?.Name} deleted user with ID {id}");
                return NoContent();
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, $"Error deleting user {id}");
                return StatusCode(500, new { message = "Ошибка при удалении пользователя" });
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
                new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString())
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
    }
}