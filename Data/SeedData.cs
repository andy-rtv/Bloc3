using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.DependencyInjection;
using System;
using System.Threading.Tasks;
using BLOC3.Areas.Identity.Data;
using Microsoft.Extensions.Logging;
using BLOC3.Models;
using Microsoft.EntityFrameworkCore;

public class SeedData
{
    public static async Task Initialize(IServiceProvider serviceProvider, UserManager<JO2024User> userManager, RoleManager<IdentityRole> roleManager)
    {
        var logger = serviceProvider.GetRequiredService<ILogger<SeedData>>();
        var context = serviceProvider.GetRequiredService<JO2024Context>();

        string[] roleNames = { "Admin", "User" };
        IdentityResult roleResult;

        foreach (var roleName in roleNames)
        {
            var roleExist = await roleManager.RoleExistsAsync(roleName);
            if (!roleExist)
            {
                roleResult = await roleManager.CreateAsync(new IdentityRole(roleName));
                if (roleResult.Succeeded)
                {
                    logger.LogInformation($"Role '{roleName}' created successfully.");
                }
                else
                {
                    logger.LogError($"Error creating role '{roleName}': {roleResult.Errors}");
                }
            }
        }

        var admin = new JO2024User
        {
            UserName = "admin@admin.com",
            Email = "admin@admin.com",
            FirstName = "Admin",
            LastName = "User",
            EmailConfirmed = true
        };

        string adminPassword = "Abc123@";
        var _user = await userManager.FindByEmailAsync("admin@admin.com");

        if (_user == null)
        {
            var createAdmin = await userManager.CreateAsync(admin, adminPassword);
            if (createAdmin.Succeeded)
            {
                await userManager.AddToRoleAsync(admin, "Admin");
                logger.LogInformation("Admin user created successfully.");
            }
            else
            {
                logger.LogError($"Error creating admin user: {createAdmin.Errors}");
            }
        }
        else
        {
            logger.LogInformation("Admin user already exists.");
        }

        // Ajout de l'offre par défaut
        if (!await context.Offres.AnyAsync(o => o.Type == "aucune"))
        {
            var defaultOffer = new Offre
            {
                Id_Offre = 1,
                Type = "aucune",
                Description = string.Empty,
                Pourcentage = 0,
                NbPersonne = null
            };

            context.Offres.Add(defaultOffer);
            await context.SaveChangesAsync();
            logger.LogInformation("Default offer added successfully.");
        }
        else
        {
            logger.LogInformation("Default offer already exists.");
        }
    }
}
