import { createClient } from "npm:@supabase/supabase-js@2";

const cors = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "authorization, apikey, content-type",
  "Access-Control-Allow-Methods": "POST, OPTIONS",
};
const yanit = (govde: unknown, status = 200) =>
  new Response(JSON.stringify(govde), { status, headers: { ...cors, "Content-Type": "application/json" } });
const TABLO: Record<string, string> = { kurum: "kurumlar", ogretmen: "hocalar", veli: "veliler", ogrenci: "ogrenciler" };

Deno.serve(async (req) => {
  if (req.method === "OPTIONS") return new Response("ok", { headers: cors });
  if (req.method !== "POST") return yanit({ hata: "Geçersiz istek" }, 405);
  const sb = createClient(Deno.env.get("SUPABASE_URL")!, Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!, {
    auth: { persistSession: false, autoRefreshToken: false },
  });
  const jeton = (req.headers.get("Authorization") ?? "").replace(/^Bearer /, "");
  const { data: kim } = await sb.auth.getUser(jeton);
  if (!kim?.user) return yanit({ hata: "Oturum geçersiz" }, 401);
  const { data: ben } = await sb.from("profiles").select("rol,ad").eq("user_id", kim.user.id).maybeSingle();
  if (!ben || !["admin", "kurum"].includes(ben.rol)) return yanit({ hata: "Bu işlem için yetkiniz yok" }, 403);

  const { islem, rol, ad, eposta, sifre } = await req.json().catch(() => ({}));
  if (typeof rol !== "string" || !Object.hasOwn(TABLO, rol) || typeof ad !== "string" || !ad) {
    return yanit({ hata: "Geçersiz kişi" }, 400);
  }
  if (ben.rol === "kurum" && rol === "kurum") return yanit({ hata: "Kurum hesabını yalnızca admin yönetir" }, 403);
  const { data: mevcut } = await sb.from("profiles").select("user_id").eq("rol", rol).eq("ad", ad);

  if (islem === "sil") {
    for (const p of mevcut ?? []) {
      const { error } = await sb.auth.admin.deleteUser(p.user_id);
      if (error) return yanit({ hata: "Hesap kaldırılamadı" }, 500);
    }
    return yanit({ tamam: true });
  }
  if (islem !== "ac") return yanit({ hata: "Geçersiz işlem" }, 400);
  if (typeof eposta !== "string" || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(eposta)) return yanit({ hata: "E-posta geçersiz" }, 400);
  if (typeof sifre !== "string" || sifre.length < 8) return yanit({ hata: "Şifre en az 8 karakter olmalı" }, 400);
  if (mevcut?.length) return yanit({ hata: "Bu kişinin zaten bir hesabı var" }, 409);
  const { data: kayit } = await sb.from(TABLO[rol]).select("ad").eq("ad", ad).maybeSingle();
  if (!kayit) return yanit({ hata: "Kişi kaydı bulunamadı; birkaç saniye sonra yeniden deneyin" }, 404);

  const { data: yeni, error } = await sb.auth.admin.createUser({ email: eposta, password: sifre, email_confirm: true });
  if (error || !yeni.user) {
    const vardir = /already|registered|exists/i.test(error?.message ?? "");
    return yanit({ hata: vardir ? "Bu e-posta zaten kayıtlı" : "Hesap açılamadı: " + (error?.message ?? "") }, 400);
  }
  const { error: p } = await sb.from("profiles").insert({ user_id: yeni.user.id, rol, ad, eposta });
  if (p) {
    await sb.auth.admin.deleteUser(yeni.user.id);
    return yanit({ hata: "Hesap açılamadı" }, 500);
  }
  return yanit({ tamam: true });
});
