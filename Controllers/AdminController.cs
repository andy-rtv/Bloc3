using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using BLOC3.Areas.Identity.Data;
using BLOC3.Models;
using System;
using System.IO;
using System.Linq;
using System.Threading.Tasks;

[Authorize(Roles = "Admin")]
public class AdminController : Controller
{
    private readonly JO2024Context _context;
    private readonly UserManager<JO2024User> _userManager;
    private readonly IWebHostEnvironment _webHostEnvironment;
    private readonly ILogger<AdminController> _logger;

    public AdminController(JO2024Context context, UserManager<JO2024User> userManager, IWebHostEnvironment webHostEnvironment, ILogger<AdminController> logger)
    {
        _context = context;
        _userManager = userManager;
        _webHostEnvironment = webHostEnvironment;
        _logger = logger;
    }

    // Affiche le tableau de bord de l'admin avec les utilisateurs, offres et événements
    public async Task<IActionResult> AdminDashboard()
    {
        var users = await _userManager.Users.ToListAsync();
        var offers = await _context.Offres.ToListAsync();
        var events = await _context.Evenements.ToListAsync();

        var salesCount = await _context.AchatEvenementOffres
            .GroupBy(a => a.OffreId)
            .Select(g => new
            {
                OffreId = g.Key,
                SalesCount = g.Count()
            })
            .ToListAsync();

        ViewBag.Offers = offers;
        ViewBag.Events = events;
        ViewBag.SalesCount = salesCount.ToDictionary(sc => sc.OffreId, sc => sc.SalesCount);

        return View(users);
    }


    // Affiche le formulaire de création d'une nouvelle offre
    public IActionResult CreateOffer()
    {
        return View();
    }

    // Traite la création d'une nouvelle offre
    [HttpPost]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> CreateOffer(Offre offer)
    {
        if (ModelState.IsValid)
        {
            _context.Add(offer);
            await _context.SaveChangesAsync();
            return RedirectToAction(nameof(AdminDashboard));
        }

        // Journalisation des erreurs de validation
        foreach (var state in ModelState)
        {
            foreach (var error in state.Value.Errors)
            {
                _logger.LogWarning("Validation error on property {Property}: {ErrorMessage}", state.Key, error.ErrorMessage);
            }
        }

        return View(offer);
    }

    // Affiche le formulaire de modification d'une offre existante
    public async Task<IActionResult> EditOffer(int? id)
    {
        if (id == null)
        {
            return NotFound();
        }

        var offer = await _context.Offres.FindAsync(id);
        if (offer == null)
        {
            return NotFound();
        }
        return View(offer);
    }

    // Traite la modification d'une offre existante
    [HttpPost]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> EditOffer(int id, [Bind("Id_Offre,Type,Description,Pourcentage,NbPersonne")] Offre offer)
    {
        if (id != offer.Id_Offre)
        {
            return NotFound();
        }

        if (ModelState.IsValid)
        {
            try
            {
                _context.Update(offer);
                await _context.SaveChangesAsync();
            }
            catch (DbUpdateConcurrencyException)
            {
                if (!OfferExists(offer.Id_Offre))
                {
                    return NotFound();
                }
                else
                {
                    throw;
                }
            }
            return RedirectToAction(nameof(AdminDashboard));
        }
        return View(offer);
    }

    // Affiche le formulaire de suppression d'une offre existante
    public async Task<IActionResult> DeleteOffer(int? id)
    {
        if (id == null)
        {
            return NotFound();
        }

        var offer = await _context.Offres.FindAsync(id);
        if (offer == null)
        {
            return NotFound();
        }

        return View(offer);
    }

    // Traite la suppression d'une offre existante
    [HttpPost, ActionName("DeleteOffer")]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> DeleteOfferConfirmed(int id)
    {
        var offer = await _context.Offres.FindAsync(id);
        if (offer == null)
        {
            return NotFound();
        }

        _context.Offres.Remove(offer);
        await _context.SaveChangesAsync();
        return RedirectToAction(nameof(AdminDashboard));
    }

    // Vérifie si une offre existe dans la base de données
    private bool OfferExists(int id)
    {
        return _context.Offres.Any(e => e.Id_Offre == id);
    }

    // Affiche le formulaire de création d'un nouvel événement
    public IActionResult CreateEvent()
    {
        return View();
    }

    // Traite la création d'un nouvel événement
    [HttpPost]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> CreateEvent(Evenement evenement, IFormFile imageFile)
    {
        if (ModelState.IsValid)
        {
            if (imageFile != null && imageFile.Length > 0)
            {
                var uploadDir = Path.Combine(_webHostEnvironment.WebRootPath, "uploads", "events");
                if (!Directory.Exists(uploadDir))
                {
                    Directory.CreateDirectory(uploadDir);
                }

                var fileName = Path.GetFileName(imageFile.FileName);
                var filePath = Path.Combine(uploadDir, fileName);

                using (var fileStream = new FileStream(filePath, FileMode.Create))
                {
                    await imageFile.CopyToAsync(fileStream);
                }

                evenement.ImgUrlPath = "/uploads/events/" + fileName;
            }

            // Convertir les dates en UTC
            evenement.DateDebut = DateTime.SpecifyKind(evenement.DateDebut, DateTimeKind.Utc);
            evenement.DateFin = DateTime.SpecifyKind(evenement.DateFin, DateTimeKind.Utc);

            _context.Add(evenement);
            await _context.SaveChangesAsync();
            return RedirectToAction(nameof(AdminDashboard));
        }

        // Ajoutez des journaux pour diagnostiquer les erreurs de validation
        foreach (var state in ModelState)
        {
            foreach (var error in state.Value.Errors)
            {
                _logger.LogWarning("Validation error on property {Property}: {ErrorMessage}", state.Key, error.ErrorMessage);
            }
        }

        return View(evenement);
    }

    // Affiche le formulaire de modification d'un événement existant
    public async Task<IActionResult> EditEvent(int? id)
    {
        if (id == null)
        {
            return NotFound();
        }

        var evenement = await _context.Evenements.FindAsync(id);
        if (evenement == null)
        {
            return NotFound();
        }
        return View(evenement);
    }

    // Traite la modification d'un événement existant
    [HttpPost]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> EditEvent(int id, Evenement evenement, IFormFile imageFile)
    {
        if (id != evenement.Id_Evenement)
        {
            return NotFound();
        }

        if (ModelState.IsValid)
        {
            try
            {
                if (imageFile != null && imageFile.Length > 0)
                {
                    var uploadDir = Path.Combine(_webHostEnvironment.WebRootPath, "uploads", "events");
                    if (!Directory.Exists(uploadDir))
                    {
                        Directory.CreateDirectory(uploadDir);
                    }

                    var fileName = Path.GetFileName(imageFile.FileName);
                    var filePath = Path.Combine(uploadDir, fileName);

                    using (var fileStream = new FileStream(filePath, FileMode.Create))
                    {
                        await imageFile.CopyToAsync(fileStream);
                    }

                    evenement.ImgUrlPath = "/uploads/events/" + fileName;
                }
                else
                {
                    // Retrieve the original event to keep the existing image path
                    var existingEvent = await _context.Evenements.AsNoTracking().FirstOrDefaultAsync(e => e.Id_Evenement == id);
                    if (existingEvent != null)
                    {
                        evenement.ImgUrlPath = existingEvent.ImgUrlPath;
                    }
                }

                // Convertir les dates en UTC
                evenement.DateDebut = DateTime.SpecifyKind(evenement.DateDebut, DateTimeKind.Utc);
                evenement.DateFin = DateTime.SpecifyKind(evenement.DateFin, DateTimeKind.Utc);

                _context.Update(evenement);
                await _context.SaveChangesAsync();
            }
            catch (DbUpdateConcurrencyException)
            {
                if (!EventExists(evenement.Id_Evenement))
                {
                    return NotFound();
                }
                else
                {
                    throw;
                }
            }
            return RedirectToAction(nameof(AdminDashboard));
        }
        return View(evenement);
    }

    // Affiche le formulaire de suppression d'un événement existant
    public async Task<IActionResult> DeleteEvent(int? id)
    {
        if (id == null)
        {
            return NotFound();
        }

        var evenement = await _context.Evenements.FindAsync(id);
        if (evenement == null)
        {
            return NotFound();
        }

        return View(evenement);
    }

    // Traite la suppression d'un événement existant
    [HttpPost, ActionName("DeleteEvent")]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> DeleteEventConfirmed(int id)
    {
        var evenement = await _context.Evenements.FindAsync(id);
        if (evenement == null)
        {
            return NotFound();
        }

        _context.Evenements.Remove(evenement);
        await _context.SaveChangesAsync();
        return RedirectToAction(nameof(AdminDashboard));
    }

    // Vérifie si un événement existe dans la base de données
    private bool EventExists(int id)
    {
        return _context.Evenements.Any(e => e.Id_Evenement == id);
    }

    // Affiche le formulaire de modification d'un utilisateur existant
    public async Task<IActionResult> EditUser(string id)
    {
        if (id == null)
        {
            return NotFound();
        }

        var user = await _userManager.FindByIdAsync(id);
        if (user == null)
        {
            return NotFound();
        }
        return View(user);
    }

    // Traite la modification d'un utilisateur existant
    [HttpPost]
    public async Task<IActionResult> EditUser(string id, JO2024User user)
    {
        if (id != user.Id)
        {
            return NotFound();
        }

        if (ModelState.IsValid)
        {
            var existingUser = await _userManager.FindByIdAsync(id);
            if (existingUser == null)
            {
                return NotFound();
            }

            existingUser.FirstName = user.FirstName;
            existingUser.LastName = user.LastName;
            existingUser.Email = user.Email;
            existingUser.UserName = user.Email; // Assuming username is same as email

            var result = await _userManager.UpdateAsync(existingUser);

            if (result.Succeeded)
            {
                return RedirectToAction(nameof(AdminDashboard));
            }

            foreach (var error in result.Errors)
            {
                ModelState.AddModelError(string.Empty, error.Description);
            }
        }
        return View(user);
    }

    // Affiche le formulaire de suppression d'un utilisateur existant
    public async Task<IActionResult> DeleteUser(string id)
    {
        if (id == null)
        {
            return NotFound();
        }

        var user = await _userManager.FindByIdAsync(id);
        if (user == null)
        {
            return NotFound();
        }

        return View(user);
    }

    // Traite la suppression d'un utilisateur existant
    [HttpPost, ActionName("DeleteUser")]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> DeleteUserConfirmed(string id)
    {
        var user = await _userManager.FindByIdAsync(id);
        if (user == null)
        {
            return NotFound();
        }

        var result = await _userManager.DeleteAsync(user);

        if (result.Succeeded)
        {
            return RedirectToAction(nameof(AdminDashboard));
        }

        foreach (var error in result.Errors)
        {
            ModelState.AddModelError(string.Empty, error.Description);
        }

        return View(user);
    }

    // Vérifie l'authenticité d'un ticket via l'URL QR code
    public async Task<IActionResult> ValidateTicket(Guid achatGuid, Guid ticketGuid)
    {
        var ticket = await _context.Tickets
            .Include(t => t.AchatEvenementOffre)
            .ThenInclude(aeo => aeo.Achat)
            .FirstOrDefaultAsync(t => t.TicketGuid == ticketGuid && t.AchatEvenementOffre.Achat.AchatGuid == achatGuid);

        if (ticket == null)
        {
            return View("InvalidTicket");
        }

        // Optionally, check if the ticket is already used
        // if (ticket.IsUsed)
        // {
        //     return View("TicketAlreadyUsed");
        // }

        // Mark the ticket as used (if applicable)
        // ticket.IsUsed = true;
        // await _context.SaveChangesAsync();

        return View("ValidTicket");
    }
}
