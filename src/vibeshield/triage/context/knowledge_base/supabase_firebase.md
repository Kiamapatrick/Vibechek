# Supabase / Firebase Misconfiguration (supabase_firebase)

## What this check detects
Client-accessible Supabase or Firebase configurations that allow unauthorized data access due to missing or misconfigured Row Level Security (RLS) / Security Rules.

## Supabase-specific patterns
- **Anon key exposure**: JWT with `role: "anon"` in client bundle (public by design, but must be paired with RLS)
- **RLS read bypass**: `GET /rest/v1/<table>` returns data without authentication → RLS not enabled or missing SELECT policy
- **RLS write bypass** (with `--allow-write-tests`): `POST /rest/v1/<table>` succeeds → missing INSERT policy
- **Common vulnerable tables**: `users`, `profiles`, `posts`, `comments`, `orders`, `products`

## Firebase-specific patterns
- **Realtime Database public read**: `https://<project>-default-rtdb.firebaseio.com/.json` returns data → rules allow unauthenticated read
- **Firestore API accessible**: `firestore.googleapis.com/v1/projects/<project>/databases/(default)/documents` returns documents → missing security rules

## Why it matters
Supabase anon keys and Firebase configs are *meant* to be public. The security model relies entirely on server-side rules (RLS / Security Rules). If those rules are missing or too permissive, anyone with the public key can read/write your database.

## Real-world impact
- User PII exposure (emails, names, addresses)
- Order/payment data leakage
- Admin panel data accessible
- Full database download via pagination

## Remediation
**Supabase:**
1. Enable RLS on every table: `ALTER TABLE <table> ENABLE ROW LEVEL SECURITY;`
2. Create restrictive policies:
   ```sql
   -- Read: only authenticated users can see their own data
   CREATE POLICY "Users can view own data" ON <table>
     FOR SELECT USING (auth.uid() = user_id);
   
   -- Write: only authenticated users can insert their own data
   CREATE POLICY "Users can insert own data" ON <table>
     FOR INSERT WITH CHECK (auth.uid() = user_id);
   ```
3. Use Supabase Dashboard → Authentication → Policies to verify

**Firebase:**
1. Realtime Database rules:
   ```json
   { "rules": { ".read": "auth != null", ".write": "auth != null" } }
   ```
2. Firestore rules:
   ```javascript
   rules_version = '2';
   service cloud.firestore {
     match /databases/{database}/documents {
       match /{document=**} {
         allow read, write: if request.auth != null;
       }
     }
   }
   ```
3. Test in Firebase Console → Rules simulator

## WSTG / ATT&CK mapping
- WSTG: WSTG-ATHZ-02
- ATT&CK: T1213