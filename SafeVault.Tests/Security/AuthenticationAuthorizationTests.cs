using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Moq;
using SaveVault.Controllers;
using SaveVault.Models;
using SaveVault.Models.ViewModels;
using System.Security.Claims;
using IdentitySignInResult = Microsoft.AspNetCore.Identity.SignInResult;

namespace SafeVault.Tests.Security
{
    public class AuthenticationAuthorizationTests
    {
        private Mock<UserManager<ApplicationUser>> GetMockUserManager()
        {
            var store = new Mock<IUserStore<ApplicationUser>>();
            var mgr = new Mock<UserManager<ApplicationUser>>(store.Object, null!, null!, null!, null!, null!, null!, null!, null!);
            mgr.Object.UserValidators.Add(new UserValidator<ApplicationUser>());
            mgr.Object.PasswordValidators.Add(new PasswordValidator<ApplicationUser>());
            return mgr;
        }

        private Mock<SignInManager<ApplicationUser>> GetMockSignInManager(Mock<UserManager<ApplicationUser>> userManager)
        {
            var contextAccessor = new Mock<IHttpContextAccessor>();
            var userPrincipalFactory = new Mock<IUserClaimsPrincipalFactory<ApplicationUser>>();
            var options = new Mock<IOptions<IdentityOptions>>();
            var logger = new Mock<ILogger<SignInManager<ApplicationUser>>>();
            var schemes = new Mock<IAuthenticationSchemeProvider>();
            var confirmation = new Mock<IUserConfirmation<ApplicationUser>>();

            return new Mock<SignInManager<ApplicationUser>>(
                userManager.Object,
                contextAccessor.Object,
                userPrincipalFactory.Object,
                options.Object,
                logger.Object,
                schemes.Object,
                confirmation.Object);
        }

        [Fact]
        public async Task Login_Should_Reject_Invalid_Credentials()
        {
            // Arrange
            var userManager = GetMockUserManager();
            var signInManager = GetMockSignInManager(userManager);
            var logger = new Mock<ILogger<AuthController>>();

            userManager.Setup(x => x.FindByEmailAsync(It.IsAny<string>()))
                .ReturnsAsync((ApplicationUser?)null);

            signInManager.Setup(x => x.PasswordSignInAsync(It.IsAny<string>(), It.IsAny<string>(), It.IsAny<bool>(), It.IsAny<bool>()))
                .ReturnsAsync(IdentitySignInResult.Failed);

            var controller = new AuthController(userManager.Object, signInManager.Object, logger.Object);

            var model = new LoginViewModel
            {
                Email = "nonexistent@example.com",
                Password = "wrongpassword"
            };

            // Act
            var result = await controller.Login(model);

            // Assert
            var viewResult = Assert.IsType<ViewResult>(result);
            Assert.False(controller.ModelState.IsValid);
            Assert.True(controller.ModelState.ContainsKey(string.Empty));
        }

        [Fact]
        public async Task Login_Should_Handle_Account_Lockout()
        {
            // Arrange
            var userManager = GetMockUserManager();
            var signInManager = GetMockSignInManager(userManager);
            var logger = new Mock<ILogger<AuthController>>();

            signInManager.Setup(x => x.PasswordSignInAsync(It.IsAny<string>(), It.IsAny<string>(), It.IsAny<bool>(), It.IsAny<bool>()))
                .ReturnsAsync(IdentitySignInResult.LockedOut);

            var controller = new AuthController(userManager.Object, signInManager.Object, logger.Object);

            var model = new LoginViewModel
            {
                Email = "locked@example.com",
                Password = "password123"
            };

            // Act
            var result = await controller.Login(model);

            // Assert
            var viewResult = Assert.IsType<ViewResult>(result);
            Assert.False(controller.ModelState.IsValid);
            Assert.Contains(controller.ModelState[string.Empty]?.Errors ?? new Microsoft.AspNetCore.Mvc.ModelBinding.ModelErrorCollection(), 
                e => e.ErrorMessage?.Contains("locked") == true);
        }

        [Fact]
        public async Task Register_Should_Enforce_Password_Complexity()
        {
            // Arrange
            var userManager = GetMockUserManager();
            var signInManager = GetMockSignInManager(userManager);
            var logger = new Mock<ILogger<AuthController>>();

            userManager.Setup(x => x.FindByEmailAsync(It.IsAny<string>()))
                .ReturnsAsync((ApplicationUser?)null);

            userManager.Setup(x => x.CreateAsync(It.IsAny<ApplicationUser>(), It.IsAny<string>()))
                .ReturnsAsync(IdentityResult.Failed(
                    new IdentityError { Description = "Password must contain uppercase letter" },
                    new IdentityError { Description = "Password must contain special character" }
                ));

            var controller = new AuthController(userManager.Object, signInManager.Object, logger.Object);

            var model = new RegisterViewModel
            {
                FullName = "Test User",
                Email = "test@example.com",
                Password = "weakpassword", // Weak password
                ConfirmPassword = "weakpassword"
            };

            // Act
            var result = await controller.Register(model);

            // Assert
            var viewResult = Assert.IsType<ViewResult>(result);
            Assert.False(controller.ModelState.IsValid);
        }

        [Fact]
        public async Task Register_Should_Prevent_Duplicate_Email()
        {
            // Arrange
            var userManager = GetMockUserManager();
            var signInManager = GetMockSignInManager(userManager);
            var logger = new Mock<ILogger<AuthController>>();

            var existingUser = new ApplicationUser
            {
                Email = "existing@example.com",
                UserName = "existing@example.com"
            };

            userManager.Setup(x => x.FindByEmailAsync("existing@example.com"))
                .ReturnsAsync(existingUser);

            var controller = new AuthController(userManager.Object, signInManager.Object, logger.Object);

            var model = new RegisterViewModel
            {
                FullName = "Test User",
                Email = "existing@example.com",
                Password = "StrongPassword123!",
                ConfirmPassword = "StrongPassword123!"
            };

            // Act
            var result = await controller.Register(model);

            // Assert
            var viewResult = Assert.IsType<ViewResult>(result);
            Assert.False(controller.ModelState.IsValid);
            Assert.Contains(controller.ModelState[string.Empty]?.Errors ?? new Microsoft.AspNetCore.Mvc.ModelBinding.ModelErrorCollection(),
                e => e.ErrorMessage?.Contains("already exists") == true);
        }

        [Fact]
        public async Task Logout_Should_Clear_Authentication()
        {
            // Arrange
            var userManager = GetMockUserManager();
            var signInManager = GetMockSignInManager(userManager);
            var logger = new Mock<ILogger<AuthController>>();

            signInManager.Setup(x => x.SignOutAsync()).Returns(Task.CompletedTask);

            var controller = new AuthController(userManager.Object, signInManager.Object, logger.Object);

            // Mock authenticated user
            var user = new ClaimsPrincipal(new ClaimsIdentity(new[]
            {
                new Claim(ClaimTypes.Name, "test@example.com"),
                new Claim(ClaimTypes.NameIdentifier, "123")
            }, "mock"));

            controller.ControllerContext = new ControllerContext()
            {
                HttpContext = new DefaultHttpContext() { User = user }
            };

            // Act
            var result = await controller.Logout();

            // Assert
            var redirectResult = Assert.IsType<RedirectToActionResult>(result);
            Assert.Equal("Index", redirectResult.ActionName);
            Assert.Equal("Home", redirectResult.ControllerName);
            signInManager.Verify(x => x.SignOutAsync(), Times.Once);
        }

        [Theory]
        [InlineData("")]
        [InlineData("invalid-email")]
        [InlineData("@example.com")]
        [InlineData("test@")]
        public void Login_Should_Validate_Email_Format(string invalidEmail)
        {
            // Arrange
            var model = new LoginViewModel
            {
                Email = invalidEmail,
                Password = "ValidPassword123!"
            };

            // Act
            var context = new System.ComponentModel.DataAnnotations.ValidationContext(model);
            var results = new List<System.ComponentModel.DataAnnotations.ValidationResult>();
            var isValid = System.ComponentModel.DataAnnotations.Validator.TryValidateObject(model, context, results, true);

            // Assert
            Assert.False(isValid);
            Assert.Contains(results, r => r.MemberNames.Contains("Email"));
        }

        [Theory]
        [InlineData("")]
        [InlineData("12345")] // Too short
        [InlineData("password")] // No uppercase, digits, or special chars
        [InlineData("Password123")] // No special characters
        public void Register_Should_Validate_Password_Requirements(string invalidPassword)
        {
            // Arrange
            var model = new RegisterViewModel
            {
                FullName = "Test User",
                Email = "test@example.com",
                Password = invalidPassword,
                ConfirmPassword = invalidPassword
            };

            // Act
            var context = new System.ComponentModel.DataAnnotations.ValidationContext(model);
            var results = new List<System.ComponentModel.DataAnnotations.ValidationResult>();
            var isValid = System.ComponentModel.DataAnnotations.Validator.TryValidateObject(model, context, results, true);

            // Assert
            Assert.False(isValid);
        }

        [Fact]
        public void Register_Should_Validate_Password_Confirmation_Match()
        {
            // Arrange
            var model = new RegisterViewModel
            {
                FullName = "Test User",
                Email = "test@example.com",
                Password = "StrongPassword123!",
                ConfirmPassword = "DifferentPassword123!"
            };

            // Act
            var context = new System.ComponentModel.DataAnnotations.ValidationContext(model);
            var results = new List<System.ComponentModel.DataAnnotations.ValidationResult>();
            var isValid = System.ComponentModel.DataAnnotations.Validator.TryValidateObject(model, context, results, true);

            // Assert
            Assert.False(isValid);
            Assert.Contains(results, r => r.MemberNames.Contains("ConfirmPassword"));
        }
    }
}