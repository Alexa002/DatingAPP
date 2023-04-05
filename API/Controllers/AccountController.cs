using System.Security.Cryptography;
using System.Text;
using API.Data;
using API.DTOs;
using API.Entities;
using API.Interfaces;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Diagnostics;

namespace API.Controllers
{
    public class AccountController : BaseApiController
    {
        private readonly DataContext _context;
        private readonly ITokenServices _tokenServices;

        public AccountController(DataContext context, ITokenServices tokenServices)
        {
            this._context = context;
            _tokenServices = tokenServices;
        }
        [HttpPost("register")] //POST api/account/register?username =dave&password=pdw
        public async Task<ActionResult<UserDTO>> Register(RegisterDto registerDto)
        {
            if(await UserExists(registerDto.Username)) return BadRequest("Username is taken");

            using var hmac = new HMACSHA512();

            var user = new AppUser{
                UserName= registerDto.Username.ToLower(),
                PasswordHash = hmac.ComputeHash(Encoding.UTF8.GetBytes(registerDto.Password)),
                PasswordSalt = hmac.Key
            };
            _context.Users.Add(user);
            await _context.SaveChangesAsync();

             return new UserDTO 
                {
                    Username= user.UserName,
                    Token = _tokenServices.CreateToken(user)
                };
        }
            [HttpPost("login")]
            public async Task<ActionResult<UserDTO>> Login(LoginDto loginDto)
            {
                var user = await _context.Users
                .Include(p => p.Photos)
                .SingleOrDefaultAsync(x => x.UserName == loginDto.Username);
                if (user == null) return Unauthorized("Invalid username");

                using var hmac = new HMACSHA512(user.PasswordSalt);

                var computeHash = hmac.ComputeHash(Encoding.UTF8.GetBytes(loginDto.Password));

                for (int i = 0; i < computeHash.Length; i++)
                {
                    if (computeHash[i] !=user.PasswordHash[i]) return Unauthorized("Invalid password");
                }
                return new UserDTO 
                {
                    Username= user.UserName,
                    Token = _tokenServices.CreateToken(user),
                    PhotoUrl = user.Photos.FirstOrDefault(x => x.IsMain)?.Url
                };
            }

       private async Task<bool> UserExists(string username)
       {
            return await _context.Users.AnyAsync(x => x.UserName == username.ToLower());
       }
    }
}