using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using WishList.Models;
using WishList.Models.AccountViewModels;
using System.Threading.Tasks;

namespace WishList.Controllers
{
    [Authorize]
    public class AccountController : Controller
    {
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly SignInManager<ApplicationUser> _signInManager;

        public AccountController(UserManager<ApplicationUser> userManager, SignInManager<ApplicationUser> signInManager)
        {
            _userManager = userManager;
            _signInManager = signInManager;
        }

        public IActionResult Index()
        {
            return View();
        }

        [HttpGet]
        [AllowAnonymous]
        public IActionResult Register()
        {
            return View("Register");
        }

        [HttpPost]
        [AllowAnonymous]
        public IActionResult Register(RegisterViewModel registerViewModel)
        {
            if (!ModelState.IsValid)
                return View(registerViewModel);

            var result = _userManager.CreateAsync(new ApplicationUser() { UserName = registerViewModel.Email, Email = registerViewModel.Email }, registerViewModel.Password).Result;
            if (!result.Succeeded)
            {
                foreach (var error in result.Errors)
                {
                    ModelState.AddModelError("Password", error.Description);
                }
                return View("Register", registerViewModel);
            }
            return RedirectToAction("Index", "Home");
        }

        [HttpGet, AllowAnonymous]
        public IActionResult Login()
        {
            return View("Login");
        }

        [HttpPost, AllowAnonymous, ValidateAntiForgeryToken]
        public IActionResult Login(LoginViewModel loginViewModel)
        {
            if (!ModelState.IsValid)
                return View("Login", loginViewModel);

            var result = _signInManager.PasswordSignInAsync(loginViewModel.Email, loginViewModel.Password, false, false).Result;
            if (!result.Succeeded)
            {
                ModelState.AddModelError(string.Empty, "Invalid login attempt");
                return View("Login", loginViewModel);
            }

            return RedirectToAction("Index", "Item");
        }

        [HttpPost, ValidateAntiForgeryToken]
        public IActionResult Logout()
        {
            _signInManager.SignOutAsync();
            return RedirectToAction("Index", "Home");
        }
    }
}
