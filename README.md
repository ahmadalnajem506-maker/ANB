# ANB FinAdmin Pro 📊

**Accounting & Financial Services Management Platform**

A professional PWA (Progressive Web App) for accounting, invoicing, expense tracking, and financial management. Built with vanilla JavaScript, HTML5, and CSS3.

---

## 🚀 Features

- ✅ **Admin & Client Portal** - Separate dashboards for administrators and clients
- ✅ **Invoice Management** - Create, edit, and track invoices with PDF export
- ✅ **Expense Tracking** - Comprehensive expense management system
- ✅ **Hours Logging** - Track billable hours and time spent
- ✅ **Dutch BTW Reports** - Official VAT quarterly reports (Dutch tax compliance)
- ✅ **Bank Statement Import** - Support for CSV and MT940 formats
- ✅ **Multilingual** - English, Dutch (NL), and Arabic (AR) with RTL support
- ✅ **Offline Support** - Full offline functionality via Service Worker
- ✅ **Cloud Sync** - Supabase integration for cloud backup
- ✅ **Installable App** - Install as native mobile app via PWA
- ✅ **Responsive Design** - Works perfectly on desktop, tablet, and mobile

---

## 📱 Installation

### Option 1: Web Browser
Visit: `https://your-cloudflare-domain.pages.dev`

### Option 2: Install as App (Recommended)

**Android / Chrome Mobile:**
1. Open the app in Chrome
2. Tap the menu (⋮) button
3. Select "Install app" or "Add to Home screen"
4. Confirm the installation

**Desktop / PWA:**
1. Open the app in Chrome/Edge
2. Click the install icon (house icon + arrow) in the address bar
3. Click "Install"

---

## 🔐 Test Accounts

### Admin
- **Email:** `admin@anbfinancial.nl`
- **Password:** `admin123`

### Clients
- **Email:** `maria@gmail.com` | **Password:** `user123`
- **Email:** `jan@expatsol.nl` | **Password:** `user123`
- **Email:** `robert@expatsol.nl` | **Password:** `user123`
- **Email:** `peter@techstart.nl` | **Password:** `user123`

---

## 📁 Project Structure

```
/
├── index.html              # Main application file (single-file architecture)
├── manifest.json           # PWA manifest configuration
├── sw.js                   # Service Worker (offline support)
├── icon-96x96.png         # App icon (small)
├── icon-192x192.png       # App icon (medium)
├── icon-512x512.png       # App icon (large)
└── README.md              # This file
```

---

## 🛠️ Technology Stack

- **Frontend:** HTML5, CSS3, Vanilla JavaScript
- **PWA:** Service Workers, Web App Manifest, Web Storage API
- **Cloud:** Supabase (PostgreSQL database)
- **Export:** jsPDF (PDF generation)
- **Internationalization:** Custom i18n system (EN/NL/AR)

---

## 📋 Key Settings

### LocalStorage Key
- `anb5` - Main data storage key

### Color Scheme
- **Primary:** Dark Green `#0A2218`
- **Accent:** Gold `#C89010`
- **Theme:** Light/Dark mode support

### Supabase Project
- **Project ID:** `zvlpeivqpiomhriukjxz`
- **Table:** `anb_data`
- **Row ID:** `anb-main`

---

## 🌐 Deployment

### Deploy to Cloudflare Pages

1. **Push to GitHub:**
   ```bash
   git add .
   git commit -m "ANB FinAdmin Pro v2.1"
   git push origin main
   ```

2. **Cloudflare Pages Setup:**
   - Go to https://dash.cloudflare.com/
   - Select "Pages" → "Create a project"
   - Connect your GitHub repository
   - Build settings:
     - **Framework preset:** None
     - **Build command:** (leave empty)
     - **Build output directory:** / (or current directory)
   - Deploy!

3. **Custom Domain (Optional):**
   - In Cloudflare Pages settings
   - Add your custom domain

---

## 🔄 Updates

To update the PWA cache version:

1. Modify content in `index.html`
2. Update `sw.js` cache version:
   ```javascript
   const CACHE_NAME = 'anb-finadmin-v2.X'; // Increment version
   ```
3. Add version parameter to manifest:
   ```html
   <link rel="manifest" href="manifest.json?v=2.X">
   ```
4. Push to GitHub
5. Cloudflare Pages auto-deploys

---

## 📞 User Guides

Available in three languages:
- **English:** Admin & Client guides
- **Dutch:** Admin & Client guides  
- **Arabic:** Admin & Client guides

---

## 🔐 Security Features

- ✅ Role-based access control (Admin/Client)
- ✅ Secure password hashing
- ✅ Session management
- ✅ Offline data encryption support
- ✅ Input validation and sanitization

---

## 📊 System Requirements

- **Browser:** Chrome 88+, Firefox 87+, Safari 14+, Edge 88+
- **Internet:** Required for sync, optional for offline use
- **Storage:** ~5-10MB local storage
- **RAM:** Minimal (~50MB)

---

## 🐛 Known Limitations

1. **2FA:** Currently simulated (not real 2FA)
2. **Email:** Notifications are logged to console (not sent)
3. **PDF:** Uses jsPDF (basic formatting)
4. **Bank Import:** Requires manual CSV conversion from PDF

---

## 🚀 Future Enhancements

- [ ] Real email notifications
- [ ] True 2-factor authentication
- [ ] Advanced PDF templates
- [ ] Direct PDF/MT940 parsing
- [ ] Mobile app (React Native version)
- [ ] Advanced analytics dashboard
- [ ] API for third-party integrations

---

## 📝 License

© 2026 ANB Financial Services. All rights reserved.

---

## 📧 Support

For issues or questions:
- **GitHub Issues:** Create an issue in the repository
- **Email:** support@anbfinancial.nl

---

**Version:** 2.1 (June 2026)  
**Last Updated:** June 27, 2026

---

## 🎯 Quick Start Checklist

- [ ] Clone repository
- [ ] Deploy to Cloudflare Pages
- [ ] Test login with admin account
- [ ] Create test invoices
- [ ] Test PDF export
- [ ] Install as app
- [ ] Test offline functionality

**Ready to deploy!** 🚀
