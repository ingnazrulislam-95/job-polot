# JobPilot

Node 20.6+ / Express / SQLite. One process serves the frontend, login page, admin screen and API.

    npm install
    cp .env.example .env     # set SESSION_SECRET, ADMIN_EMAILS, ADMIN_PASSWORD
    npm run dev              # http://localhost:3000 -> redirects to /login.html

## Accounts
- Customers: email + password, or LinkedIn (OpenID Connect). Register BASE_URL/auth/linkedin/callback in your LinkedIn app.
- Admin: first email in ADMIN_EMAILS + ADMIN_PASSWORD, signed in at /login.html, then opens /admin.
  Admin emails cannot be self-registered. Without LinkedIn keys, the LinkedIn button opens a demo customer (development only).

## Monthly subscription (Stripe)
1. Stripe Dashboard: create a Product with a monthly recurring Price; copy the price id to STRIPE_PRICE_ID.
2. Put the secret key in STRIPE_SECRET_KEY. Enable the Customer portal (Settings > Billing > Customer portal).
3. Webhook endpoint: BASE_URL/webhook/stripe with events checkout.session.completed and
   customer.subscription.created / updated / deleted. Copy its signing secret to STRIPE_WEBHOOK_SECRET.
   Local testing: stripe listen --forward-to localhost:3000/webhook/stripe
4. Free users get free_ai_limit AI letters per day, Pro users pro_ai_limit (both editable in /admin).
Before charging customers, add terms, privacy and refund pages and check VAT handling for your country.
Email verification and password reset are not built yet.

Production: NODE_ENV=production behind HTTPS, and back up jobpilot.db.
