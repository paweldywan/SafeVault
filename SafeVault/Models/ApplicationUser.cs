using Microsoft.AspNetCore.Identity;
using System.ComponentModel.DataAnnotations;

namespace SafeVault.Models
{
    public class ApplicationUser : IdentityUser
    {
        [Required]
        [StringLength(100, MinimumLength = 2)]
        [RegularExpression(@"^[a-zA-Z\s]+$", ErrorMessage = "Name can only contain letters and spaces")]
        public string FullName { get; set; } = string.Empty;

        [DataType(DataType.DateTime)]
        public DateTime? LastLoginDate { get; set; }

        public bool IsActive { get; set; } = true;
    }
}