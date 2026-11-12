# ANTI-HACK - app Android (Kivy). L'interfaccia e' a chat; il motore e' in core.py
import os, threading, time
from kivy.app import App
from kivy.clock import Clock
from kivy.core.window import Window
from kivy.graphics import Color, RoundedRectangle
from kivy.metrics import dp
from kivy.uix.boxlayout import BoxLayout
from kivy.uix.button import Button
from kivy.uix.label import Label
from kivy.uix.popup import Popup
from kivy.uix.scrollview import ScrollView
from kivy.uix.textinput import TextInput
from kivy.utils import escape_markup, platform

import core

BG = (0.15, 0.15, 0.14, 1)
BOT = (0.20, 0.20, 0.19, 1)
ME = (0.28, 0.26, 0.23, 1)
ACC = (0.85, 0.47, 0.34, 1)
LEVELS = [("SICURO", "2e9d4f", "Nessun problema rilevato."),
          ("SOSPETTO", "d18a00", "Aprilo solo se ti fidi della fonte."),
          ("PERICOLOSO", "e04646", "NON aprirlo. Eliminalo.")]


class Bubble(Label):
    def __init__(self, text, color=BOT, **kw):
        super().__init__(text=text, markup=True, size_hint_y=None, halign="left", valign="middle",
                         color=(0.94, 0.93, 0.90, 1), **kw)
        self.bind(width=self._wrap, texture_size=self._fit, pos=self._draw, size=self._draw)
        with self.canvas.before:
            Color(*color)
            self.bg = RoundedRectangle(pos=self.pos, size=self.size, radius=[dp(14)])

    def _wrap(self, *a):
        self.text_size = (self.width - dp(24), None)

    def _fit(self, *a):
        self.height = self.texture_size[1] + dp(24)

    def _draw(self, *a):
        self.bg.pos, self.bg.size = self.pos, self.size


class AntiHackApp(App):
    title = "Anti-Hack"

    def build(self):
        core.init(self.user_data_dir)
        Window.clearcolor = BG
        root = BoxLayout(orientation="vertical", padding=dp(8), spacing=dp(8))
        root.add_widget(Label(text="[b]Anti-Hack[/b]", markup=True, size_hint_y=None, height=dp(44), font_size=dp(20)))
        self.scroll = ScrollView()
        self.chat = BoxLayout(orientation="vertical", size_hint_y=None, spacing=dp(8), padding=dp(4))
        self.chat.bind(minimum_height=self.chat.setter("height"))
        self.scroll.add_widget(self.chat)
        root.add_widget(self.scroll)
        bottom = BoxLayout(orientation="vertical", size_hint_y=None, height=dp(112), spacing=dp(6))
        bottom.add_widget(Button(text="Carica un file", background_normal="", background_color=ACC,
                                 font_size=dp(18), on_release=self.pick_file))
        row = BoxLayout(spacing=dp(6))
        row.add_widget(Button(text="Database", on_release=lambda *a: self.db_prompt()))
        row.add_widget(Button(text="API key", on_release=lambda *a: self.key_popup()))
        bottom.add_widget(row)
        root.add_widget(bottom)
        return root

    def on_start(self):
        self.pending = {}
        self.say("Ciao! Sono il tuo scanner anti-hacking. Tocca [b]Carica un file[/b] e ti dico se e' sicuro.")
        cnt, _ = core.db_info()
        if cnt == 0:
            self.db_prompt()
        if not core.has_key():
            self.say("Per usare anche gli antivirus online di VirusTotal tocca [b]API key[/b] (facoltativo).")

    # ---------- utilita' interfaccia ----------
    def ui(self, fn, *args):
        Clock.schedule_once(lambda dt: fn(*args), 0)

    def say(self, text, who="bot"):
        b = Bubble(text, ME if who == "me" else BOT)
        self.chat.add_widget(b)
        Clock.schedule_once(lambda dt: setattr(self.scroll, "scroll_y", 0), 0.1)
        return b

    def ask(self, text, options):
        self.say(text)
        row = BoxLayout(size_hint_y=None, height=dp(48), spacing=dp(6))

        def make(cb):
            def pressed(*a):
                self.chat.remove_widget(row)
                cb()
            return pressed
        for label, cb in options:
            row.add_widget(Button(text=label, on_release=make(cb)))
        self.chat.add_widget(row)
        Clock.schedule_once(lambda dt: setattr(self.scroll, "scroll_y", 0), 0.1)

    def card(self, level, title, lines):
        name, col, _ = LEVELS[level]
        txt = "[b]%s: [color=%s]%s[/color][/b]" % (title, col, name)
        for l in lines:
            txt += "\n- " + escape_markup(l)
        self.say(txt)

    def finish(self, level):
        self.card(level, "Verdetto finale", [LEVELS[level][2]])

    # ---------- scelta del file ----------
    def pick_file(self, *a):
        if platform != "android":
            self.say("La scelta del file funziona solo su Android.")
            return
        from androidstorage4kivy import Chooser
        self.chooser = Chooser(self.on_picked)
        self.chooser.choose_content("*/*")

    def on_picked(self, uris):
        if uris:
            threading.Thread(target=self.scan_worker, args=(uris[0],), daemon=True).start()

    def scan_worker(self, uri):
        try:
            from androidstorage4kivy import SharedStorage
            path = SharedStorage().copy_from_shared(uri)
            name = os.path.basename(path)
            self.ui(self.say, "File: " + escape_markup(name), "me")
            self.ui(self.say, "Analizzo il file...")
            r = core.scan_file(path, name)
        except Exception as e:
            self.ui(self.say, "Errore: " + escape_markup(str(e)))
            return
        self.ui(self.show_result, r, path)

    # ---------- risultati ----------
    def show_result(self, r, path):
        self.say("SHA-256:\n" + r["sha256"])
        L = r["local"]
        base = L["level"]
        self.card(L["level"], "Controllo sul telefono", L["reasons"] or ["Nessun segnale sospetto."])
        E = r["engine"]
        if E["status"] == "hit":
            self.card(2, "Motore personale", ["Riconosciuto come: " + E["name"]])
            base = 2
        elif E["status"] == "clean":
            self.say("Motore personale: non corrisponde a nessuna delle %d firme di malware noti (database del %s). "
                     "Un malware nuovo o modificato potrebbe non essere riconosciuto." % (E["count"], E["date"]))
        else:
            self.say("Il motore personale non ha ancora il database. Tocca [b]Database[/b] per scaricarlo.")
        v = r["vt"]
        st = v["status"]
        if st == "found":
            self.vt_show(v, base)
            self.cleanup(path)
        elif st == "unknown":
            def yes():
                threading.Thread(target=self.upload_worker, args=(path, r["name"], base), daemon=True).start()

            def no():
                self.cleanup(path)
                self.finish(base)
            self.ask("VirusTotal non conosce questo file. Per analizzarlo devo caricarlo, e allora il file sara' "
                     "visibile a VirusTotal. Vuoi farlo?", [("Carica su VirusTotal", yes), ("No, resta privato", no)])
        else:
            msgs = {"badkey": "API key non valida. Tocca API key per cambiarla.",
                    "limit": "Troppe richieste a VirusTotal (limite gratuito). Riprova tra un minuto.",
                    "offline": "Non riesco a collegarmi a VirusTotal: controlla internet."}
            if st in msgs:
                self.say(msgs[st])
            self.cleanup(path)
            self.finish(base)

    def vt_show(self, v, base):
        s = v["stats"]
        tot = sum(s.values()) or 1
        mal, sus = s.get("malicious", 0), s.get("suspicious", 0)
        lvl = 2 if mal >= 3 else (1 if (mal >= 1 or sus >= 1) else 0)
        lines = ["Segnalato da %d antivirus su %d" % (mal + sus, tot)]
        for n, res in v["flagged"][:8]:
            lines.append("%s: %s" % (n, res))
        self.card(lvl, "Antivirus online", lines)
        self.finish(max(base, lvl))

    def cleanup(self, path):
        try:
            os.remove(path)
        except Exception:
            pass

    def upload_worker(self, path, name, base):
        self.ui(self.say, "Carico il file su VirusTotal...")
        aid, err = core.vt_upload(path, name)
        self.cleanup(path)
        if err:
            self.ui(self.say, err)
            self.ui(self.finish, base)
            return
        self.ui(self.say, "Analisi in corso, puo' volerci 1-3 minuti...")
        for _ in range(40):
            time.sleep(10)
            p = core.vt_poll(aid)
            if p["status"] == "completed":
                self.ui(self.vt_show, p, base)
                return
        self.ui(self.say, "Tempo scaduto, riprova piu' tardi.")

    # ---------- database ----------
    def db_prompt(self):
        self.ask("Il motore personale usa il database di ClamAV (antivirus open source): lo scarichi una volta "
                 "(diverse centinaia di MB, meglio con il Wi-Fi) e poi controlli i file offline. "
                 "Tieni l'app aperta durante il download.",
                 [("Scarica / aggiorna", self.db_start), ("Piu' tardi", lambda: None)])

    def db_start(self):
        w = self.say("Avvio...")

        def progress(msg):
            self.ui(setattr, w, "text", escape_markup(msg))

        def work():
            try:
                n = core.update_db(progress)
                self.ui(setattr, w, "text", "Database pronto: %d firme di malware noti." % n)
            except Exception as e:
                self.ui(setattr, w, "text", "Errore: %s\nControlla internet e lo spazio libero, poi riprova." %
                        escape_markup(str(e)))
        threading.Thread(target=work, daemon=True).start()

    # ---------- API key ----------
    def key_popup(self):
        box = BoxLayout(orientation="vertical", spacing=dp(8), padding=dp(8))
        box.add_widget(Label(text="Incolla la API key gratuita di VirusTotal\n(dal tuo profilo su virustotal.com)",
                             size_hint_y=None, height=dp(56)))
        inp = TextInput(multiline=False, password=True, size_hint_y=None, height=dp(44))
        box.add_widget(inp)
        ok = Button(text="Salva", size_hint_y=None, height=dp(48))
        box.add_widget(ok)
        pop = Popup(title="API key VirusTotal", content=box, size_hint=(0.92, None), height=dp(260))

        def save(*a):
            k = inp.text.strip()
            if not k:
                return
            pop.dismiss()
            self.say("Verifico la chiave...")
            threading.Thread(target=self.key_worker, args=(k,), daemon=True).start()
        ok.bind(on_release=save)
        pop.open()

    def key_worker(self, k):
        st, det = core.validate_key(k)
        msgs = {"ok": "Chiave valida. Test riuscito: il file di prova EICAR e' segnalato da %d antivirus." % det,
                "badkey": "Chiave non valida. Controlla di averla copiata tutta.",
                "limit": "Chiave salvata, ma ora c'e' troppo traffico per verificarla.",
                "offline": "Chiave salvata, ma non riesco a verificarla: controlla internet."}
        self.ui(self.say, msgs.get(st, "Errore nella verifica della chiave."))


if __name__ == "__main__":
    AntiHackApp().run()
