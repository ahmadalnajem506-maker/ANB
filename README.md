# 📊 ANB Financial Services - Admin & Client Portal

A modern, single-file Progressive Web App (PWA) for ZZP (self-employed) accounting and financial management in the Netherlands.

## ✨ Features

### Admin Portal
- 📄 Invoice management (create, edit, export to PDF)
- 🧾 Expense tracking with document uploads & camera capture
- 📁 Document management (files, receipts, proofs)
- 💬 Client messaging system with real-time notifications
- 👥 Client workspace management
- 📊 Financial reports & BTW calculations
- 🏦 Bank statement imports (MT940, CSV)
- ⏰ Time tracking & hours logging
- 📈 Dashboard with key metrics

### Client Portal
- 📄 View invoices & download PDFs
- 🧾 Submit expenses with document uploads
- 📸 Capture receipts with camera
- 💬 Messaging with ANB Financial
- 📊 View financial overview
- 🔔 Real-time notifications for new documents & messages

## 🎯 Technical Stack

- **HTML5** - Single file architecture
- **CSS3** - Modern responsive design (dark theme)
- **JavaScript (ES6+)** - Client-side logic
- **localStorage** - Local data persistence
- **Supabase** - Cloud sync & backend (optional)
- **jsPDF** - PDF export functionality
- **PWA** - Install as app on mobile/desktop

## 🚀 Quick Start

### Local Development
```bash
# Python 3
python -m http.server 8000

# Then open: http://localhost:8000/ANB_FinAdmin_Pro.html
```

### Demo Credentials
```
Admin:
- Email: info@anbfinancial.nl
- Password: admin123

Client:
- Email: info@expatsol.nl
- Password: client123
```

## 📱 Mobile Features
- ✅ File uploads from device
- ✅ Camera capture for receipts
- ✅ Touch-optimized interface
- ✅ Offline-capable (localStorage)
- ✅ Installable as web app

## 🌐 Languages Supported
- 🇬🇧 English
- 🇳🇱 Dutch (Nederlands)
- 🇸🇦 Arabic (العربية) - RTL support

## 📊 Data Structure

### Local Storage (anb5)
```javascript
{
  clients: [],      // Client list
  invoices: [],     // Invoices
  expenses: [],     // Expenses
  documents: [],    // Uploaded files
  hours: [],        // Time entries
  messages: [],     // Conversations
  settings: {}      // App settings
}
```

## 🔒 Security Features
- Client-side encryption ready
- Secure localStorage isolation
- No external API calls by default
- Supabase integration for cloud sync

## 📦 Deployment

### Cloudflare Pages (Recommended)
1. Push to GitHub
2. Connect repo to Cloudflare Pages
3. Set build output to root directory
4. Deploy automatically on every push

### Other Options
- Netlify
- Vercel
- GitHub Pages
- Any static host

## 📝 License
MIT License - See LICENSE file

## 👨‍💼 Author
Ahmad Al-Najem
Senior Financial Controller | ANB Financial Services

---

**Built for ZZP professionals in the Netherlands** 🇳🇱

For support or questions: contact@anbfinancial.nl
