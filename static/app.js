const SUPABASE_URL = "https://ubldspvbpejtnxniqvne.supabase.co";
const SUPABASE_ANON_KEY = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6InVibGRzcHZicGVqdG54bmlxdm5lIiwicm9sZSI6ImFub24iLCJpYXQiOjE3ODI5ODU2OTEsImV4cCI6MjA5ODU2MTY5MX0.p9XbrjMnQuHmdk1erB5wWrpnw4D5APpdxoe-M0S2-10";
const sb = supabase.createClient(SUPABASE_URL, SUPABASE_ANON_KEY);

// Expose session globally so index.html can access it via getJwt()
window._supaSession = null;

// Sign in/out — called by sidebar buttons in index.html
window._supaSignIn = async () => {
  await sb.auth.signInWithOAuth({
    provider: "google",
    options: { redirectTo: location.origin }
  });
};

window._supaSignOut = async () => {
  await sb.auth.signOut();
};

// Auth state bridge — fires on sign in, sign out, token refresh
sb.auth.onAuthStateChange((_event, session) => {
  window._supaSession = session;
  if (typeof window._onSessionChange === "function") {
    window._onSessionChange(session);
  }
});

// Restore existing session on page load
(async () => {
  const { data } = await sb.auth.getSession();
  window._supaSession = data.session;
  if (typeof window._onSessionChange === "function") {
    window._onSessionChange(data.session);
  }
})();