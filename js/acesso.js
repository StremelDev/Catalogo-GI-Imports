"use strict";
// Catálogo GI IMPORTS — acesso com usuário e senha.
// O catálogo fica cifrado (AES-256-GCM) em dados/catalogo.bin. Cada usuário tem
// uma cópia da chave do catálogo cifrada com a própria senha (PBKDF2-SHA-256).
(() => {
  const SESSION_KEY = "gi-imports-catalogo";
  const encoder = new TextEncoder();
  const form = document.getElementById("login-form");
  const userInput = document.getElementById("usuario");
  const passwordInput = document.getElementById("senha");
  const errorBox = document.getElementById("login-error");
  const button = document.getElementById("login-button");

  const fromBase64 = text => Uint8Array.from(atob(text), c => c.charCodeAt(0));
  const toBase64 = bytes => btoa(String.fromCharCode(...bytes));

  function session(action, value) {
    try {
      if (action === "get") return sessionStorage.getItem(SESSION_KEY);
      if (action === "set") sessionStorage.setItem(SESSION_KEY, value);
      if (action === "clear") sessionStorage.removeItem(SESSION_KEY);
    } catch { /* navegação privada: segue sem lembrar */ }
    return null;
  }

  async function userId(name) {
    const digest = await crypto.subtle.digest("SHA-256", encoder.encode("gi-imports|" + name.trim().toLowerCase()));
    return [...new Uint8Array(digest)].map(b => b.toString(16).padStart(2, "0")).join("");
  }

  async function catalogKeyFor(name, password) {
    const response = await fetch("dados/usuarios.json", { cache: "no-store" });
    if (!response.ok) throw new Error("rede");
    const db = await response.json();
    const entry = db.users[await userId(name)];
    if (!entry) return null;
    const base = await crypto.subtle.importKey("raw", encoder.encode(password), "PBKDF2", false, ["deriveKey"]);
    const passwordKey = await crypto.subtle.deriveKey(
      { name: "PBKDF2", salt: fromBase64(entry.salt), iterations: db.iterations, hash: "SHA-256" },
      base, { name: "AES-GCM", length: 256 }, false, ["decrypt"],
    );
    try {
      return new Uint8Array(await crypto.subtle.decrypt({ name: "AES-GCM", iv: fromBase64(entry.iv) }, passwordKey, fromBase64(entry.key)));
    } catch {
      return null;
    }
  }

  async function openCatalog(rawKey) {
    const key = await crypto.subtle.importKey("raw", rawKey, "AES-GCM", false, ["decrypt"]);
    const response = await fetch("dados/catalogo.bin", { cache: "no-store" });
    if (!response.ok) throw new Error("rede");
    const data = new Uint8Array(await response.arrayBuffer());
    const plain = await crypto.subtle.decrypt({ name: "AES-GCM", iv: data.slice(0, 12) }, key, data.slice(12));
    const payload = JSON.parse(new TextDecoder().decode(plain));

    window.__catalogPhotos = payload.photos;
    const app = document.getElementById("app");
    app.innerHTML = payload.html;
    document.getElementById("login").remove();
    app.hidden = false;
    document.title = payload.title;

    const script = document.createElement("script");
    script.textContent = payload.js;
    document.body.appendChild(script);

    document.getElementById("logout").addEventListener("click", () => {
      session("clear");
      location.reload();
    });
  }

  function showError(message) {
    errorBox.textContent = message;
    errorBox.hidden = false;
  }

  form.addEventListener("submit", async event => {
    event.preventDefault();
    errorBox.hidden = true;
    button.disabled = true;
    button.textContent = "Verificando…";
    try {
      const rawKey = await catalogKeyFor(userInput.value, passwordInput.value);
      if (!rawKey) {
        showError("Usuário ou senha incorretos. Confira e tente de novo.");
        passwordInput.select();
        return;
      }
      button.textContent = "Abrindo o catálogo…";
      await openCatalog(rawKey);
      session("set", toBase64(rawKey));
    } catch {
      showError("Não foi possível abrir o catálogo. Verifique a internet e tente de novo.");
    } finally {
      if (document.body.contains(button)) {
        button.disabled = false;
        button.textContent = "Entrar";
      }
    }
  });

  // Mesma aba: reabre sem pedir a senha de novo até clicar em "Sair" ou fechar a aba.
  const saved = session("get");
  if (saved) {
    openCatalog(fromBase64(saved)).catch(() => session("clear"));
  } else {
    userInput.focus();
  }
})();
