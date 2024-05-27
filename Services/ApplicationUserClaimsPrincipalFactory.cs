using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Options;
using System.Security.Claims;
using System.Threading.Tasks;
using BLOC3.Areas.Identity.Data;

public class ApplicationUserClaimsPrincipalFactory : UserClaimsPrincipalFactory<JO2024User, IdentityRole>
{
    public ApplicationUserClaimsPrincipalFactory(
        UserManager<JO2024User> userManager,
        RoleManager<IdentityRole> roleManager,
        IOptions<IdentityOptions> optionsAccessor)
        : base(userManager, roleManager, optionsAccessor)
    {
    }

    protected override async Task<ClaimsIdentity> GenerateClaimsAsync(JO2024User user)
    {
        var identity = await base.GenerateClaimsAsync(user);
        return identity;
    }
}
