using System;
using System.Linq;
using System.Threading.Tasks;
using Amazon.AspNetCore.Identity.Cognito;
using Amazon.CognitoIdentityProvider;
using Amazon.CognitoIdentityProvider.Model;
using Amazon.Extensions.CognitoAuthentication;
using Amazon.Runtime.Internal.Transform;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using WebAdvert.Web.Models.Accounts;

// For more information on enabling MVC for empty projects, visit https://go.microsoft.com/fwlink/?LinkID=397860

namespace MyWebAdvert.Web.Controllers
{
    public class AccountsController : Controller
    {
        //AWS-Se inyectan desde el servicio de cognito

        private readonly CognitoUserPool _pool;
        private readonly UserManager<CognitoUser> _userManager;
        private readonly SignInManager<CognitoUser> _signInManager;


        public AccountsController(SignInManager<CognitoUser> signInManager, UserManager<CognitoUser> userManager,
            CognitoUserPool pool)
        {
            _signInManager = signInManager;
            _userManager = userManager;
            _pool = pool;
        }

        public IActionResult Signup()
        {
            var model = new SignupModel();
            return View(model);
        }

        [HttpPost]
        public async Task<IActionResult> Signup(SignupModel model)
        {
            try
            {
                if (ModelState.IsValid)
                {
                    var user = _pool.GetUser(model.Email);
                    if (user.Status != null)
                    {
                        ModelState.AddModelError("UserExists", "User with this email already exists");
                        return View(model);
                    }

                    //user.Attributes.Add(CognitoAttributesConstants.Name, model.Email);
                    user.Attributes.Add(CognitoAttribute.Name.AttributeName, model.Email);
                    user.Attributes.Add(CognitoAttribute.Email.AttributeName, model.Email);
                    var createdUser = await _userManager.CreateAsync(user, model.Password).ConfigureAwait(false);

                    if (createdUser.Succeeded) return RedirectToAction("Confirm");
                    else ModelState.AddModelError("createdUserError", string.Join<string>(" - ", createdUser.Errors.Select(error => error.Description).ToList()));
                }


            }
            catch (Exception ex)
            {
                ModelState.AddModelError("Somne kind of error", ex.Message);

            }
            return View(model);
        }

        [HttpGet]
        public IActionResult Confirm(ConfirmModel model)
        {
            return View(model);
        }

        [HttpPost]
        [ActionName("Confirm")]
        public async Task<IActionResult> ConfirmPost(ConfirmModel model)
        {
            if (ModelState.IsValid)
            {
                var user = await _userManager.FindByEmailAsync(model.Email).ConfigureAwait(false);
                if (user == null)
                {
                    ModelState.AddModelError("NotFound", "A user with the given email address was not found");
                    return View(model);
                }

                var result = await ((CognitoUserManager<CognitoUser>)_userManager)
                    .ConfirmSignUpAsync(user, model.Code, true).ConfigureAwait(false);
                if (result.Succeeded) return RedirectToAction("Index", "Home");
                else ModelState.AddModelError("ConfirmPost", string.Join<string>(" - ", result.Errors.Select(error => error.Description).ToList()));
                //foreach (var item in result.Errors) ModelState.AddModelError(item.Code, item.Description);

                return View(model);
            }

            return View(model);
        }

        [HttpGet]
        public IActionResult Login(LoginModel model)
        {
            return View(model);
        }

        [HttpPost]
        [ActionName("Login")]
        public async Task<IActionResult> LoginPost(LoginModel model)
        {
            if (ModelState.IsValid)
            {
                var result = await _signInManager.PasswordSignInAsync(model.Email,
                    model.Password, model.RememberMe, false).ConfigureAwait(false);
                if (result.Succeeded)
                    return RedirectToAction("Index", "Home");
                ModelState.AddModelError("LoginError", "Email and password do not match");
            }

            return View("Login", model);
        }
        [HttpGet]
        [ActionName("Signout")]
        public async Task<IActionResult> Signout()
        {
            if (User.Identity.IsAuthenticated) await _signInManager.SignOutAsync().ConfigureAwait(false);
            return RedirectToAction("Index", "home");
        }

        [HttpGet]
        [ActionName("ForgotPassword")]
        public IActionResult ForgotPassword()
        {
            ForgotPassword forgotPassword = new ForgotPassword();
            return View(forgotPassword);
        }

        [HttpPost]
        [ActionName("ForgotPassword")]
        public async Task<IActionResult> ForgotPassword(ForgotPassword forgotPassword)
        {
            var email = forgotPassword.Email;
            var user = _pool.GetUser(forgotPassword.Email);
            await user.ForgotPasswordAsync();

            ConfirmNewPasswordModel confirmNewPasswordModel = new ConfirmNewPasswordModel {Email= forgotPassword.Email };

            return View("ConfirmNewPassword", confirmNewPasswordModel);
        }


        [HttpPost]
        [ActionName("ConfirmNewPassword")]
        public async Task<IActionResult> ConfirmNewPassword(ConfirmNewPasswordModel confirmNewPasswordModel)
        {//string confirmation, string email, string newpassword)
            //if (ModelState.IsValid)
            {
                var user = _pool.GetUser(confirmNewPasswordModel.Email);
                var result = await user.ConfirmForgotPasswordAsync(confirmNewPasswordModel.Code, confirmNewPasswordModel.Password);
                //if (result.Succeeded)
                    return RedirectToAction("Index", "Home");

            //}
            //return View(confirmNewPasswordModel);
        }
    }
}

