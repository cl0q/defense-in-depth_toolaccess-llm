# Bedrohungsmodell & Anwendungsszenario

Konkretisierung des Angriffsmodells, der Akteure und des Datenzugriffs für die
Bachelorarbeit *„Sicherheit von LLMs mit Datenbankzugriff"*. Ergänzt
`brainstorm2.md` um die vom Betreuer geforderten Punkte: **wer greift wie auf
welche Daten zu**, **welcher UseCase**, **welche Gefahren**, und **woher ein
Nutzer wissen kann, dass die Abwehr greift**.

> **Hinweis (12. Juni 2026):** Leitfassung ist
> `angriffsvektoren-und-verteidigung.md`. Diese Datei wurde angeglichen:
> **Schreib-/Modifikations-Angriffe** (W1–W5, LLM06), **dreistufige
> Infrastruktur-Verteidigung DC-a/b/c** und **I6** (parametrisierte Templates)
> sind ergänzt. Vollständige Erfolgsziele (G-*), Experiment-Matrix und
> korrigierte Hypothesen H3a′/H3c′ siehe Leitdatei.

---

## 1. Designentscheidung: geteiltes System mit Zugriff auf *alle* Daten

Es gibt zwei mögliche Datenwelten — nur eine ist forschungswürdig:

| Variante | Beschreibung | Bewertung |
|----------|--------------|-----------|
| **Isolation pro Nutzer** | Jeder Nutzer hat einen DB-Account/Datensatz, der nur seine eigenen Daten sieht. | Trivial sicher durch Isolation auf Verbindungsebene → **es gibt im System nichts zu schützen**. Kein Forschungsthema. |
| **Geteiltes Multi-Tenant-System** | *Ein* LLM-Dienst, *eine* Datenbank mit den Daten **aller** Tenants. Zugriffskontrolle muss **pro Anfrage im System** entscheiden, wer was sehen darf. | **Genau hier liegt die Angriffsfläche.** Das ist das realistische Enterprise-Szenario und der Gegenstand dieser Arbeit. |

> **Festlegung:** Diese Arbeit untersucht ausschließlich das **geteilte
> Multi-Tenant-System**. Die Sicherheitsschicht muss innerhalb des Systems
> identitäts-/rollenabhängig durchsetzen, welche Daten an eine Anfrage
> zurückfließen — nicht die Datenbank pauschal einschränken.

### Warum nicht ein eigenes LLM pro Tenant?
Ein dediziertes Modell + isolierte DB pro Tenant wäre durch Isolation trivial
sicher (kein Cross-Tenant-Problem). In realistischer Größenordnung
(zehntausende Tenants) ist das aber **wirtschaftlich und betrieblich
unmöglich**: VRAM-, Hosting- und Wartungskosten explodieren. Dasselbe
ökonomische Argument, das ein **kleines, schnelles Target-Modell** rechtfertigt,
erzwingt auch **Multi-Tenancy** — ein geteilter Dienst über geteilte Daten.
**Erst dadurch wird Zugriffskontrolle zum harten Problem** und damit zum
Gegenstand dieser Arbeit.

---

## 2. Anwendungsszenario (abstrakt, übertragbar)

Bewusst **domänenunabhängig** gehalten: eine **Multi-Tenant-SaaS-Marktplatz-
Plattform**. Kern ist nicht die Branche, sondern die **rollenbasierte
Datengrenze** — übertragbar auf beliebige Enterprise-Kontexte.

### Akteure / Rollen

| Rolle | Beschreibung | Tenant-Grenze |
|-------|--------------|---------------|
| **Plattform / Admin** | Betreiber des Marktplatzes | übergreifend |
| **Händler / Verkäufer** *(„Middleman")* | Verkauft über die Plattform; hat eigene Produkte, Bestellungen, Umsätze, Kundenkontakte | **= Tenant** |
| **Kunde / Käufer** | Kauft bei Händlern; hat eigenes Profil, eigene Bestellungen, Zahlungsdaten | **= Tenant** |

### Übertragbarkeit (ein Satz in der Arbeit)
> Plattform → DATEV · Händler/Tenant → Steuerkanzlei · Kunde → Mandant.
> Die Rollen- und Datengrenzen sind strukturell identisch; die Befunde gelten
> für jedes rollenbasierte Multi-Tenant-System mit sensiblen Daten.

Der **UseCase**: ein LLM-Chatbot erlaubt jeder Rolle, Daten in natürlicher
Sprache abzufragen (NL-to-SQL), z. B. *„Zeig mir meine Bestellungen aus Q3"*.
Produktivitätswerkzeug über sensible, mandantengetrennte Daten.

---

## 3. Datenmodell & Berechtigungsmatrix (wer darf was)

Eine geteilte PostgreSQL-DB mit allen Tenant-Daten. Beispielschema:

```
platform_users(id, role, merchant_id?)        merchants(id, name, payout_account)
customers(id, name, email, address)           products(id, merchant_id, name, price, internal_cost)
orders(id, customer_id, merchant_id, total, status, note)
order_items(order_id, product_id, qty, price)  payments(id, order_id, card_token, amount)
```

**Berechtigungsmatrix** (das Herz des Bedrohungsmodells — „wer greift auf was zu"):

> Diese Matrix zeigt die **Lese**-Sicht. Die vollständige Matrix inkl. getrennter
> **Schreib-/Modifikations-Rechte (R/W)** pro Rolle steht in
> `angriffsvektoren-und-verteidigung.md` §2.

| Datenobjekt | Kunde | Händler | Admin |
|-------------|-------|---------|-------|
| Eigenes Profil / eigene Bestellungen | ✅ | ✅ (eigene) | ✅ |
| **Andere** Kunden (Profil, Bestellungen, PII) | ❌ | nur eingeschränkte Liefer-/Kontaktdaten *eigener* Käufer | ✅ |
| **Andere** Händler (Umsatz, Kundenliste, `internal_cost`) | ❌ | ❌ (Konkurrenzschutz) | ✅ |
| `products.internal_cost` (Marge) | ❌ | ✅ (eigene Produkte) | ✅ |
| `merchants.payout_account` (Auszahlungskonto) | ❌ | ✅ (eigenes) | ✅ |
| `payments.card_token` (Zahlungsdaten) | ❌ (max. maskiert) | ❌ | eingeschränkt |
| Plattformweite Aggregate | ❌ | ❌ | ✅ |

Die Schutzaufgabe lautet: **Egal was das LLM generiert — eine Anfrage darf nur
die Zellen/Zeilen zurückliefern, die der Berechtigungsmatrix für die
*authentifizierte* Rolle entsprechen.**

---

## 4. Akteure: legitimer Nutzer vs. Angreifer

| | Identität | Darf | Will (Angriff) |
|--|-----------|------|----------------|
| **Legitimer Nutzer** | Authentifiziert, Rolle aus Verzeichnisdienst (LDAP/AD) | gemäß Matrix (Abschnitt 3) | — |
| **Angreifer A1 — Cross-Tenant (horizontal)** | Gültiger Login (z. B. Kunde/Händler) | dito | Per Prompt Injection an Daten **anderer Tenants** kommen (fremde Bestellungen, Konkurrenz-Umsätze, Kundenlisten) |
| **Angreifer A2 — Eskalation (vertikal)** | Gültiger Login niedriger Rolle | dito | Daten **oberhalb** der eigenen Rolle lesen (z. B. Kunde → Händler-Auszahlungskonto oder Plattform-Aggregate) |
| **Angreifer A3 — Spalten-/Sensitivitäts-Eskalation** | Gültiger Login | Zeile sichtbar | Eine **gesperrte Spalte** innerhalb erlaubter Zeilen extrahieren (`card_token`, `internal_cost`) |
| **Angreifer A4 — Indirekte (Stored) Injection** | beliebig | — | Schadtext in Daten platzieren (z. B. `product.name`, `order.note`); kapert das LLM, **wenn es diese Daten für einen anderen Nutzer liest** → Exfiltration |
| **Angreifer A5 — Schreib-/Modifikations-Angriff** | Gültiger Login | gemäß Matrix | **Unautorisiert schreiben**: fremde Bestellung ändern (Cross-Tenant-Write), eigene Rolle auf `admin` setzen (Privilege Escalation), `orders.total`/`payments.amount` manipulieren, destruktiv löschen (`DROP`/Massen-`DELETE`), `merchants.payout_account` umbiegen (Finanzbetrug) |

> **Primärer Angreifer dieser Arbeit:** der **authentifizierte Insider
> (A1/A2/A3/A5)** — das klassische und realistischste Multi-Tenant-SaaS-Risiko,
> jetzt inkl. **Schreib-/Modifikations-Angriffen** (A5, LLM06). A4 (indirekte
> Injection, vgl. Greshake et al.) als zweite Schiene für LLM01.

---

## 5. Angriffsklassen & OWASP-Mapping

Verknüpfung der Angreifer-Szenarien mit den OWASP-LLM-Top-10-Klassen (2025):

| Szenario | OWASP | Gefahr / Schaden |
|----------|-------|------------------|
| A1/A2/A3 direkt, A4 indirekt | **LLM01** Prompt Injection | Einstiegsvektor für alle folgenden |
| Datenabfluss fremder/sensibler Datensätze | **LLM02** Sensitive Information Disclosure | DSGVO-Bruch, Vertrauensverlust, Wettbewerbsschaden |
| Ungefilterte Ausführung des generierten SQL (Cross-Tenant-Query erreicht DB, UNION-Exfiltration) | **LLM05** Improper Output Handling | unautorisierter Datenzugriff auf Ausführungsebene |
| Schreib-/Löschoperationen ohne Berechtigung — A5: Cross-Tenant-Write, Privilege Escalation, destruktive/Finanzbetrugs-Writes | **LLM06** Excessive Agency | Datenmanipulation, Integritätsverlust, Finanzschaden |

> Vollständige Aufschlüsselung der Lese- (R1–R3) und Schreib-Angriffe (W1–W5) +
> Stored Injection (S1) inkl. gebündelter Erfolgsziele G-* in
> `angriffsvektoren-und-verteidigung.md` §3–§4.

---

## 6. Abwehr-Schichten (vergleichbare, einzeln schaltbare Layer)

Zentraler Beitrag der Arbeit = **Wirksamkeits- und Kostenmessung jeder Schicht
einzeln und in Kombination**. Jeder Layer ist unabhängig an-/abschaltbar.

| Layer | Maßnahme | Wirkebene | Status |
|-------|----------|-----------|--------|
| **D0 — Baseline** | Freies NL-to-SQL, privilegierte DB-Verbindung (sieht alles), keine Filter | — | Kern |
| **DA — System-Prompt-Härtung** | Strikte Anweisungen, Few-Shot für sicheres Verhalten, Daten/Instruktions-Trennung (*Spotlighting*) | LLM (probabilistisch) | Kern |
| **DB — Input-Guardrail** | Leichtgewichtiger Klassifikator (z. B. Llama-Guard) + RegEx auf bösartige Muster | LLM/Filter (probabilistisch) | Kern |
| **DC-a — Per-Rolle Least-Privilege** | Eigene DB-Rolle je App-Rolle; Operation/Tabellen-`GRANT`s (kein `UPDATE` auf `platform_users`, kein `DROP` für Kunden-Verbindung) | Infrastruktur (**deterministisch**) | Kern |
| **DC-b — Row-Level Security** | Authentifizierte Rolle (LDAP/AD) bis in die DB-Session propagiert; RLS `USING` (Lese-Isolation) **+** `WITH CHECK` (Schreib-Isolation) filtern **pro Anfrage** gemäß Matrix | Infrastruktur (**deterministisch**) | Kern (Herzstück) |
| **DC-c — Column-Masking** | Sensible Spalten (`card_token`, `internal_cost`) physisch aus zugänglicher Sicht entfernen/maskieren (Spalten-`GRANT` oder View) | Infrastruktur (**deterministisch**) | Kern |
| **D++ — Defense-in-Depth** | Sequentielle Kombination DA + DB + DC-a/b/c | gestaffelt | Kern |
| **I6 — Eingeschränkte Tool-Schnittstelle** | Statt freiem SQL nur **geprüfte, parametrisierte Query-Templates** (Function-Calling); LLM füllt nur Parameter → eliminiert LLM05 konstruktionsbedingt | Architektur (**deterministisch**) | Referenz-Obergrenze **+ empfohlene Produktivarchitektur** |
| *DF — Output-/Egress-Filter* | Antwort vor Auslieferung auf fremde **Canary-Token / PII-Muster** scannen, ggf. blocken | Filter (deterministisch) | *Kandidat (optional)* |

> **DC-b ist das Herzstück:** RLS hat zwei Hälften — `USING` bestimmt *was du
> siehst*, `WITH CHECK` bestimmt *was du schreiben darfst*. Eine einzige saubere
> DB-Mechanik deckt damit Cross-Tenant-**Read** *und* -**Write** *und*
> Privilege-Escalation ab. Selbst ein gejailbreaktes LLM, das
> `SELECT * FROM orders` oder `UPDATE orders …` erzeugt, erhält/ändert durch RLS
> nur die eigenen Tenant-Zeilen. Das ist der Kern von FF3/H3c′ (deterministisch
> vs. probabilistisch).
>
> **I6** ist die architektonische Konsequenz: Würde die Idee real im Unternehmen
> eingesetzt, müsste sie als I6 implementiert werden — dann entfällt freies
> NL-to-SQL vollständig (IT-sicherheitstechnisch überlegen). Im Experiment dient
> I6 als obere Vergleichsgrenze, nicht als gleichwertiger NL-to-SQL-Messlayer.
> Details: `angriffsvektoren-und-verteidigung.md` §5.

---

## 7. Assurance: „Woher weiß der Nutzer, dass die Abwehr greift?"

Zwei klar getrennte Ebenen:

**Ebene 1 — Nachweis durch die Forschung (für die Arbeit):**
Das **deterministische Oracle** (DB-Statement-Log, State-Diff, Canary-Match,
korreliert über Trace-ID) liefert ein hartes, LLM-unabhängiges ASR über
n Wiederholungen. → *Wie oft* hält eine Schicht, statistisch belegt.

**Ebene 2 — Vertrauen des Endnutzers (die eigentliche Betreuer-Frage):**

> Bei **probabilistischen** Schichten (DA, DB) ist nie eine Garantie möglich,
> nur eine Statistik („hält in 97 %"). Ein einziger erfolgreicher Jailbreak
> genügt → die Skepsis des Nutzers ist berechtigt.
>
> Bei **deterministischen** Schichten (DC-a/b/c, I6) ist eine **strukturelle
> Garantie** möglich: Die Datenbank gibt fremde Zeilen *physisch nicht* heraus
> und akzeptiert verbotene Writes nicht — unabhängig vom LLM-Output, weil die
> Filterung auf einer Ebene passiert, die das LLM nicht beeinflussen kann. Das
> ist **beweisbar**, nicht statistisch.

Ergänzend zur Transparenz:
- **Externe Prüfbarkeit (der eigentliche Beweis):** RLS-Policies, Grants und
  Templates sind statisch lesbar und zertifizierbar — unabhängig vom Modell.
- **Audit-/Provenance-Anzeige (Usability-Hilfe, nicht Beweis):** Dem Nutzer
  sichtbar machen, *welche* Tabellen/Tenants für eine Antwort berührt wurden.
  Achtung: Diese Anzeige ist selbst Systemoutput und könnte von einem
  kompromittierten System gefälscht werden — der Beweis ist der extern prüfbare
  deterministische Layer, nicht die Anzeige.

> **Antwort an den Betreuer:** Vertrauen entsteht nicht durch „die KI verhält
> sich brav", sondern durch **deterministische Garantien an der richtigen
> Architekturebene + Nachvollziehbarkeit**. Genau das ist die anwendungs-
> relevante Konsequenz aus FF3/H3c′.

---

## 8. Bezug zu den Forschungsfragen

- **FF1 (Wirksamkeit):** Berechtigungsmatrix (Abschnitt 3) definiert eindeutig,
  was ein „erfolgreicher" Angriff ist (Matrix-Verletzung bei Lesen **oder**
  Schreiben) → präzises ASR pro Layer und Erfolgsziel.
- **FF2 (Kosten):** Jeder Layer wird inkrementell auf Latenz/Energie gemessen.
- **FF3 (Architektur vs. Modell):** DC-a/b/c (deterministisch) vs. DA/DB
  (probabilistisch) — die zentrale Vergleichsachse; I6 als architektonische
  Obergrenze. Korrigierte Hypothesen H3a′/H3c′ siehe
  `angriffsvektoren-und-verteidigung.md` §6.

---

## 9. Offene Punkte

- [ ] Konkretes DB-Schema + RLS-Policies (`USING` **und** `WITH CHECK`) +
      Spalten-Grants/Views + Canary-Datensätze pro Sensitivitätsstufe finalisieren.
- [ ] Identitäts-Propagation spezifizieren: LDAP/AD-Lookup → Gateway →
      DB-Session-Variable (`SET app.current_user / app.current_tenant`) → RLS.
- [ ] I6-Template-Katalog definieren (parametrisierte Operationen je Rolle) —
      zugleich Spezifikation der Produktivarchitektur.
- [ ] „Legitime Anfragen"-Set (Read + Write) definieren (für False-Positive-Rate /
      Usability).
- [ ] Mapping-Satz Plattform→DATEV final in die Einleitung übernehmen.
- [ ] Folien aktualisieren (Schreib-Angriffe, DC-Stufen, I6 als Empfehlung).
