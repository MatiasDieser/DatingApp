using System.Security;
using API.Data;
using API.Entities;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;

namespace API.Controllers
{

    [Authorize]
    public class UsersController : BaseApiController
    {
        
        private readonly DataContext _context;

        public UsersController(DataContext context)
        {
            _context = context;           
        }

        [HttpGet]
        public async Task<ActionResult<IEnumerable<AppUser>>> getUsers()
        {
            var users = await _context.Users.ToListAsync();
            return users;
        }

        [HttpGet("{id}")]
        public async Task<ActionResult<AppUser>> getUserById(int id)
        {
            var user = await _context.Users.FindAsync(id);

            return user;
        }
    }
}