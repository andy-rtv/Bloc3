using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;
using BLOC3.Areas.Identity.Data;
using BLOC3.Models;

namespace BLOC3.Controllers
{
    [Authorize(Roles = "User")] // Autorise uniquement les utilisateurs avec le rôle "User"
    public class UserController : Controller
    {
        private readonly JO2024Context _context;

        // Constructeur pour injecter le contexte de base de données
        public UserController(JO2024Context context)
        {
            _context = context;
        }

        // Affiche le tableau de bord de l'utilisateur
        public async Task<IActionResult> UserDashboard()
        {
            // Récupère l'ID de l'utilisateur connecté
            var userId = User.FindFirstValue(ClaimTypes.NameIdentifier);

            // Récupère les achats de l'utilisateur connecté
            var achats = await _context.Achats
                .Where(a => a.Id_Utilisateur == userId)
                .Select(a => new
                {
                    a.DateAchat,
                    a.MontantTotal,
                    a.AchatGuid
                })
                .ToListAsync();

            return View(achats);
        }

        // Affiche les détails d'un achat spécifique
        public async Task<IActionResult> AchatDetails(Guid id)
        {
            // Récupère l'achat avec les événements et les tickets associés
            var achat = await _context.Achats
                .Include(a => a.AchatEvenementOffres)
                    .ThenInclude(aeo => aeo.Evenement)
                .Include(a => a.AchatEvenementOffres)
                    .ThenInclude(aeo => aeo.Tickets)
                .FirstOrDefaultAsync(a => a.AchatGuid == id);

            // Si l'achat n'existe pas, retourne une erreur 404
            if (achat == null)
            {
                return NotFound();
            }

            return View(achat);
        }
    }
}
