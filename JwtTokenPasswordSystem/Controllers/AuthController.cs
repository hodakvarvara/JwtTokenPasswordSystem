using JwtTokenPasswordSystem.Data;
using JwtTokenPasswordSystem.Models;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using Org.BouncyCastle.Crypto.Generators;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;

namespace JwtTokenPasswordSystem.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthController : ControllerBase
    {

        private readonly IConfiguration _configuration;
        private readonly AppDbContext _context;

        public AuthController(AppDbContext context, IConfiguration configuration)
        {
            _context = context;
            _configuration = configuration;
        }

        /// <summary>
        /// Регистрация
        /// Хеширует введенный пароль пользователя с помощью BCrypt, 
        /// сохраняет имя пользователя и хеш пароля в объекте user и
        /// возвращает его в виде ответа.
        /// </summary>
        /// <param name="userDTO"></param>
        /// <returns></returns>
        [HttpPost("registrate")]
        public IActionResult RegisterUser([FromBody] UserDto userDTO)
        {
            if (userDTO == null || string.IsNullOrEmpty(userDTO.UserName) || string.IsNullOrEmpty(userDTO.Password))
            {
                return StatusCode(400, "логин или пароль не переданы"); // Если логин или пароль не переданы
            }

            try
            {
                if (_context.Users.Any(u => u.UserName == userDTO.UserName))
                {
                    return StatusCode(400, " пользователь с таким логином уже существует"); // Если пользователь с таким логином уже существует
                }
            }
            catch (Exception ex)
            {
                return StatusCode(400, " Error Db");
            }

            /* Bcrypt — алгоритм хеширования паролей, 
            * он использует генерацию случайной "соли" и замедляет процесс 
            * хеширования с помощью алгоритма Blowfish. 
            */
            string passwordHash = BCrypt.Net.BCrypt.HashPassword(userDTO.Password); // Хеширование пароля

            var newUser = new User { UserName = userDTO.UserName, PasswordHash = passwordHash };
            _context.Users.Add(newUser);
            _context.SaveChanges();

            return StatusCode(201, "Успешная регистрация нового пользователя"); // Успешная регистрация нового пользователя
        }




        /// <summary>
        /// Вход пользователя
        /// </summary>
        /// <param name="request"></param>
        /// <returns></returns>
        [HttpPost("login")]
        public ActionResult Login([FromBody] UserDto request)
        {
            //Проверяет, существует ли пользователь с таким именем
            var user = _context.Users.FirstOrDefault(u => u.UserName == request.UserName);

            if (user == null || !BCrypt.Net.BCrypt.Verify(request.Password, user.PasswordHash))
            {
                return Unauthorized(); // Пользователь не аутентифицирован
            }


            //Если пользователь найден и пароль совпадает,
            //генерирует JWT-токен и возвращает его в качестве ответа.
            string accessToken = CreateAccessToken(user);
            var refreshToken = GenerateRefreshToken(user);
            return Ok("Token set in cookie");
        }


        [HttpPost("refresh")]
        public async Task<ActionResult<string>> RefreshToken()
        {
            var refreshToken = Request.Cookies["Refresh-Token"];
            var hmac = new HMACSHA512(Encoding.UTF8.GetBytes(
                _configuration.GetSection("AppSettings:RefreshToken").Value!));
            var validationParameters = new TokenValidationParameters
            {
                ValidateIssuerSigningKey = true,
                ValidateAudience = false,
                ValidateIssuer = false,
                ValidateLifetime = true,
                IssuerSigningKey = new SymmetricSecurityKey(hmac.Key),

            };

            JwtSecurityTokenHandler jwtSecurityTokenHandler = new();
            try
            {
                jwtSecurityTokenHandler.ValidateToken(refreshToken, validationParameters,
                    out SecurityToken validatedToken);

                // Попытка декодирования и извлечения утверждений
                var tokenHandler = new JwtSecurityTokenHandler();
                var jwtToken = tokenHandler.ReadJwtToken(refreshToken);

                // Получение утверждений (claims) из токена
                var claims = jwtToken.Claims;

                // Печать утверждений для примера


                var user = _context.Users.FirstOrDefault(u => u.UserId == Convert.ToInt64(claims.First().Value));
                string token = CreateAccessToken(user);
                var newRefreshToken = GenerateRefreshToken(user);
                return StatusCode(200, "Токены успешно обновлены");
            }
            catch (Exception)
            {
                return StatusCode(403, "Ошибка генерации токенов");
            }


        }

        /// <summary>
        /// Генерация нового токена обновления
        /// чтобы продлить срок действия аутентификации без повторного ввода учетных данных
        /// 
        /// </summary>
        /// <returns></returns>
        private string GenerateRefreshToken(User user)
        {

            //создание списка утверждений (claims) в токене (например, имя пользователя).
            List<Claim> claims = new List<Claim>
            {
                new Claim(ClaimTypes.Name, user.UserId.ToString())
            };

            // конфигурацию для получения ключа
            var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(
                _configuration.GetSection("AppSettings:RefreshToken").Value!));

            // создает учетные данные для подписи токена
            // использование алгоритма подписи HMAC-SHA512 для генерации подписи токена.
            var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256); //учетные данные подпись

            // JWT токен содержит указанные утверждения, время истечения и подпись
            var refreshToken = new JwtSecurityToken(
                    claims: claims,
                    expires: DateTime.Now.AddDays(7),//дата истечения срока действия
                    signingCredentials: creds //учетные данныe
                );

            var jwt = new JwtSecurityTokenHandler().WriteToken(refreshToken); // записываем токен

            HttpContext.Response.Cookies.Append("Refresh-Token", jwt, new CookieOptions
            {
                HttpOnly = true, // Устанавливаем флаг HttpOnly
                Secure = true        // Другие настройки, если нужно
            });
            return jwt;
        }


        /// <summary>
        /// Создает JWT (JSON Web Token) для пользователя.
        /// </summary>
        /// <param name="user"></param>
        /// <returns></returns>
        private string CreateAccessToken(User user)
        {
            /*Объекты claim представляют некоторую информацию о пользователе, 
             * которую мы можем использовать для авторизации в приложении. 
             * Например, у пользователя может быть определенный возраст, город, страна...*/

            //создание списка утверждений (claims) в токене (например, имя пользователя). 
            List<Claim> claims = new List<Claim>
            {
                new Claim(ClaimTypes.Name, user.UserName)
            };

            // конфигурацию для получения ключа
            var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(
                _configuration.GetSection("AppSettings:AccessToken").Value!));

            // создает учетные данные для подписи токена
            // использование алгоритма подписи HMAC-SHA512 для генерации подписи токена.
            var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha512Signature); //учетные данные подпись

            // JWT токен содержит указанные утверждения, время истечения и подпись
            var accessToken = new JwtSecurityToken(
                    claims: claims,
                    expires: DateTime.Now.AddMinutes(30),//дата истечения срока действия
                    signingCredentials: creds //учетные данныe
                );

            var jwt = new JwtSecurityTokenHandler().WriteToken(accessToken); // записываем токен

            HttpContext.Response.Cookies.Append("Access-Token", jwt, new CookieOptions
            {
                HttpOnly = true, // Устанавливаем флаг HttpOnly
                Secure = true        // Другие настройки, если нужно
            });
            return jwt;
        }
    }
}
