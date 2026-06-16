# Angriffsvektoren & Verteidigung (überarbeiteter Plan)

> Konsolidierte, gelockte Fassung nach dem Brainstorm vom 12. Juni 2026.
> Erweitert `bedrohungsmodell.md` und `brainstorm2.md` um **Schreib-/
> Modifikations-Angriffe**, eine **dreistufige Infrastruktur-Verteidigung (DC)**
> und die **eingeschränkte Tool-Schnittstelle (I6)** als empfohlene
> Produktivarchitektur. Löst zugleich den Hypothesen-Widerspruch (Defense C neu
> vs. altes LLM02-Caveat) auf.
>
> **Status der Kernentscheidungen (gelockt):**
> - ✅ Schreib-/Modifikations-Angriffe werden aufgenommen (LLM06 voll bespielt).
> - ✅ Infrastruktur-Verteidigung DC in drei messbaren Stufen (DC-a/b/c).
> - ✅ I6 (parametrisierte Templates) als Architektur-Decke **und** als die
>   Architektur, die bei echtem Unternehmenseinsatz zu implementieren wäre —
>   dann entfällt freies NL-to-SQL (IT-sicherheitstechnisch überlegen).
> - ✅ Domäne bleibt Marktplatz (Käufer/Händler/Plattform); Schreib-UseCases
>   werden innerhalb dieser Domäne definiert.

---

## 1. Domäne & Rollen (unverändert, jetzt mit Schreiben)

Die Domäne bleibt der **Multi-Tenant-SaaS-Marktplatz**. Sie mappt strukturell
auf die Steuer-Welt, ohne dass die Steuerdomäne selbst modelliert wird:

| Marktplatz-Rolle | Mapping (Steuer-Welt) | Tenant-Grenze |
|------------------|------------------------|---------------|
| **Plattform / Admin** | Unternehmen / Plattformbetreiber | übergreifend |
| **Händler / Verkäufer** (*„Middleman"*) | Steuerkanzlei | = Tenant |
| **Kunde / Käufer** | Arbeitnehmer / Mandant | = Tenant |

**Warum Schreiben dazugehört:** In der Zieldomäne (Steuerberater bearbeitet
Mandantendaten, gibt Erklärungen frei) sind Schreiboperationen real. Die
Marktplatz-Domäne bildet das natürlich ab — es muss nichts erfunden werden.

### Schreib-UseCases (legitim) je Rolle

| Rolle | Lesen (legitim) | **Schreiben / Modifizieren (legitim)** |
|-------|------------------|-----------------------------------------|
| Kunde | eigene Bestellungen, eigenes Profil | Bestellung aufgeben, eigenes Profil ändern, eigene Bestellung stornieren, Bewertung schreiben |
| Händler | eigene Produkte, Umsätze, eigene Käufer (eingeschränkt) | Produktpreis ändern, Bestellstatus setzen, Rückerstattung auslösen, **eigenes** Auszahlungskonto ändern |
| Admin | alles | Rollen verwalten, plattformweite Einstellungen |

> Mapping-Beispiel: „Händler ändert Bestellstatus" ↔ „Steuerberater gibt
> Erklärung eines Mandanten frei". „Kunde ändert eigenes Profil" ↔
> „Arbeitnehmer reicht Belege/Stammdaten ein".

---

## 2. Datenmodell & Berechtigungsmatrix (Lesen **und** Schreiben)

Geteilte PostgreSQL-DB mit allen Tenant-Daten. Beispielschema:

```
platform_users(id, role, tenant_id, merchant_id?)   merchants(id, tenant_id, name, payout_account)
customers(id, tenant_id, name, email, address)      products(id, merchant_id, name, price, internal_cost)
orders(id, customer_id, merchant_id, total, status, note)
order_items(order_id, product_id, qty, price)       payments(id, order_id, card_token, amount)
audit_log(id, actor, action, target, ts)            -- append-only
```

### Berechtigungsmatrix — Lesen (R) und Schreiben (W)

| Datenobjekt | Kunde R | Kunde W | Händler R | Händler W | Admin |
|-------------|:--:|:--:|:--:|:--:|:--:|
| Eigenes Profil / eigene Bestellung | ✅ | ✅ | ✅ (eigene) | ✅ (eigene) | ✅ |
| **Fremde** Kunden (PII, Bestellungen) | ❌ | ❌ | nur eigene Käufer (eingeschr.) | ❌ | ✅ |
| **Fremde** Händler (Umsatz, `internal_cost`) | ❌ | ❌ | ❌ | ❌ | ✅ |
| `products.price` / `products.internal_cost` | nur `price` | ❌ | ✅ (eigene) | ✅ `price` / ❌ Cost-Manipulation | ✅ |
| `merchants.payout_account` | ❌ | ❌ | ✅ (eigenes) | ✅ (eigenes) | ✅ |
| `payments.card_token` / `amount` | maskiert | ❌ | ❌ | ❌ | eingeschr. |
| `platform_users.role` (eigene Rolle) | ❌ | ❌ | ❌ | ❌ | ✅ |
| `orders.total` / `orders.status` | lesen | ❌ (total) | ✅ (eigene) | ✅ `status` / ❌ `total` willkürlich | ✅ |
| `audit_log` | ❌ | ❌ (append-only) | ❌ | ❌ (append-only) | lesen |

**Schutzaufgabe:** Egal was das LLM generiert — eine Anfrage darf nur die
Zellen/Zeilen **lesen oder verändern**, die der Matrix für die *authentifizierte*
Rolle entsprechen.

---

## 3. Angriffsvektoren (vollständig) mit OWASP-LLM-Top-10-2025-Mapping

> OWASP-Klassen 2025 im Fokus (Bezeichnungen verifiziert gegen *OWASP Top 10 for
> LLM Applications v2.0*, `LLMAll_en-US_FINAL`):
> **LLM01:2025** Prompt Injection · **LLM02:2025** Sensitive Information
> Disclosure · **LLM05:2025** Improper Output Handling · **LLM06:2025**
> Excessive Agency.
>
> Belege aus dem Dokument: LLM05 nennt explizit *„LLM-generated SQL queries are
> executed without proper parameterization, leading to SQL injection"* sowie
> *privilege escalation* — exakt die Mechanik der Schreib-Angriffe. LLM06 führt
> als Ursachen *excessive functionality / permissions / autonomy* mit Wirkung
> über die gesamte CIA-Achse — passt auf W1–W5.

### 3.1 Lese-Angriffe (Exfiltration → LLM02)

| # | Angriff | Beispiel | OWASP |
|---|---------|----------|-------|
| **R1** | Cross-Tenant-Read (horizontal) | Händler A liest Umsatz/Kundenliste von Händler B | LLM02 (Vektor LLM01) |
| **R2** | Vertical-Read (Eskalation) | Kunde liest Plattform-Aggregate / fremdes Auszahlungskonto | LLM02 |
| **R3** | Column-Read (Sensitivität) | gesperrte Spalte in sichtbarer Zeile ziehen (`card_token`, `internal_cost`) | LLM02 |

### 3.2 Schreib-Angriffe (Manipulation → LLM06, Mechanik LLM05) — **NEU**

| # | Angriff | Beispiel | OWASP |
|---|---------|----------|-------|
| **W1** | Cross-Tenant-Write (horizontal) | Händler A ändert Preis/Bestellung von Händler B | LLM06 (Mechanik LLM05) |
| **W2** | Vertical-Write / Privilege Escalation | Kunde setzt eigene Rolle auf `admin` (`UPDATE platform_users SET role=…`) | LLM06 |
| **W3** | Self-serving Write (eigener Tenant, gesperrtes Feld) | Kunde setzt eigene `orders.total = 0` / drückt `payments.amount` | LLM06 |
| **W4** | Destruktiver Write | `DELETE FROM orders`, `DROP TABLE`, Massen-`UPDATE` | LLM06 + LLM05 |
| **W5** | Finanzbetrug-Write | `merchants.payout_account` auf Angreiferkonto umbiegen, Fake-Refund | LLM06 |

### 3.3 Stored / Indirect Injection (verbindet Schreiben + Lesen → LLM01)

| # | Angriff | Beispiel | OWASP |
|---|---------|----------|-------|
| **S1** | Stored / Second-Order Injection | Angreifer **schreibt** Schadtext in `product.name`/`order.note`; liest später das LLM **eines anderen Nutzers** (z. B. Admin) diese Zeile, wird es gekapert → Exfiltration/Aktion | LLM01 indirekt → LLM02/LLM06 |

> Voraussetzung für S1 im Aufbau: DB-Freitext muss tatsächlich wieder in den
> Modellkontext gelangen (das LLM fasst Rohzeilen zusammen). Diese Bedingung wird
> im Datenpfad explizit hergestellt, sonst ist S1 nicht auslösbar.

### Bewusst nicht zentral
- **LLM07** System Prompt Leakage — optionale Nebenmetrik (kann der Angreifer
  Defense A auslesen?), kein Kern.
- **LLM08** Vector/Embedding — nur mit RAG/Embeddings relevant → raus.
- **LLM10** Unbounded Consumption — taucht als Massen-Exfiltration auf, durch
  Infra-Caps (DC) abgedeckt, keine eigene Klasse.

---

## 4. Abzudeckende Erfolgsziele (G-*) — gegen Matrix-Explosion gebündelt

Sechs Erfolgsziele, jedes mit hartem, deterministischem Oracle. Erfolg = jede
Verletzung der Berechtigungsmatrix (Lesen *oder* Schreiben).

| Ziel | Bündelt | OWASP | Oracle |
|------|---------|-------|--------|
| **G-R1** Cross-Tenant-Read | R1 | LLM02 | Canary-Token fremder Tenant erscheint in Ausgabe |
| **G-R2** Column/Sensitivity-Read | R2, R3 | LLM02 | gesperrte Spalte / fremde Aggregatzeile in Ausgabe |
| **G-W1** Unautorisierter Write (cross/self) | W1, W3 | LLM06 | State-Diff: Zeile außerhalb Matrix verändert |
| **G-W2** Privilege Escalation / Finanzbetrug | W2, W5 | LLM06 | State-Diff: `role`/`payout_account` unautorisiert geändert |
| **G-W3** Destruktiver Write | W4 | LLM05/06 | DB-Log: DDL/Massen-DML hat DB erreicht |
| **G-S1** Stored Injection (2nd order) | S1 | LLM01→02/06 | Canary aus präparierter Zeile in Opfer-Ausgabe |

Eintritt jeweils über LLM01 (Prompt Injection), Mechanik über LLM05 (ungefiltertes
SQL erreicht DB).

---

## 5. Verteidigungs-Schichten

### 5.1 Probabilistische Layer (LLM-seitig) — bleiben wie gehabt

| Layer | Maßnahme | Wirkebene |
|-------|----------|-----------|
| **D0 — Baseline** | freies NL-to-SQL, privilegierte DB-Verbindung, keine Filter | — |
| **DA — System-Prompt-Härtung** | strikte Anweisungen, Few-Shot, Daten/Instruktions-Trennung (Spotlighting) | LLM (probabilistisch) |
| **DB — Input-Guardrail** | leichtgewichtiger Klassifikator (z. B. Llama-Guard) + RegEx auf bösartige Muster | LLM/Filter (probabilistisch) |

> DA/DB sind naturgemäß **probabilistisch** und damit umgehbar — das ist
> erwartet und Teil der These (FF3/H3c). Sie bleiben unverändert als
> Vergleichsbasis und decken den Rest ab, den Infra prinzipiell nicht greifen
> kann (siehe §6).

### 5.2 Deterministische Infrastruktur-Verteidigung DC — drei messbare Stufen

Inkrementell schaltbar, erzählbare Steigerung **Operation → Zeile → Spalte**.
Alle wirken **unterhalb** des LLM in der DB-Engine — unabhängig von der
Jailbreak-Qualität.

| Stufe | Mechanik (PostgreSQL) | Killt deterministisch | Wirkebene |
|-------|------------------------|------------------------|-----------|
| **DC-a — Per-Rolle Least-Privilege** | eigene DB-Rolle je App-Rolle; Operation/Tabellen-`GRANT`s (kein `UPDATE` auf `platform_users`, kein `DROP` für Kunden-Verbindung) | W2 (Escalation), W4 (Destruktiv) | Infrastruktur |
| **DC-b — Row-Level Security (USING + WITH CHECK)** | Identität via `SET app.current_tenant` (aus LDAP/AD-Rolle) propagiert; `USING` filtert Lesen, `WITH CHECK` filtert Schreiben | R1 (Cross-Tenant-Read), W1 (Cross-Tenant-Write), Rest W2 | Infrastruktur |
| **DC-c — Column-Masking / Views** | sensible Spalten (`card_token`, `internal_cost`) physisch aus zugänglicher Sicht entfernen/maskieren (Spalten-`GRANT` oder View) | R3 (Column-Read) | Infrastruktur |

> **Das Herzstück ist DC-b (RLS mit `WITH CHECK`):** RLS hat zwei Hälften —
> `USING` bestimmt *was du siehst*, `WITH CHECK` bestimmt *was du schreiben
> darfst*. Eine einzige, saubere DB-Mechanik deckt damit Cross-Tenant-**Read**
> *und* -**Write** *und* Privilege-Escalation ab — auf einer Ebene, die das LLM
> nicht beeinflussen kann. Das ist die beweisbare Story für H3c.

#### 5.2.1 Identitäts-Propagation (LDAP/AD → DB-Session) — der Schlüssel zu DC-b

Damit RLS überhaupt „weiß", für wen sie filtert, muss die **authentifizierte
Identität bis in die DB-Session durchgereicht** werden. Das ist der eigene
Mechanismus hinter DC-b und zugleich die ursprüngliche LDAP-Idee dieser Arbeit:
Nicht das LLM entscheidet über Zugriff, sondern die **out-of-band** ermittelte
Rolle steuert die deterministische DB-Filterung.

**Kette (pro Anfrage):**

1. **Authentifizierung & Rollen-Lookup:** Der Nutzer ist gegen den
   Verzeichnisdienst (**LDAP/AD**) authentifiziert; das Gateway ermittelt Rolle
   und Tenant aus dem LDAP/AD-Eintrag — **unabhängig vom Prompt-Inhalt**.
2. **Vertrauensgrenze:** Diese Identität wird *nie* aus dem LLM-Output abgeleitet
   (das wäre manipulierbar), sondern serverseitig aus der Session/dem Token.
3. **Propagation in die DB-Session:** Das Gateway öffnet/benutzt die DB-Verbindung
   und setzt pro Anfrage Session-Variablen, z. B.
   `SET app.current_user = '…'; SET app.current_tenant = '…'; SET ROLE …;`
   (gesetzt als parametrisierter, nicht vom LLM beeinflussbarer Wert).
4. **RLS wertet aus:** Die Policies lesen `current_setting('app.current_tenant')`
   in `USING` (Lesen) und `WITH CHECK` (Schreiben) → deterministische
   Pro-Anfrage-Filterung gemäß Berechtigungsmatrix.

```mermaid
sequenceDiagram
    participant U as Nutzer (Rolle)
    participant DS as LDAP/AD
    participant GW as API-Gateway
    participant LLM as Target LLM
    participant DB as PostgreSQL (RLS)
    U->>GW: Prompt + Auth-Token
    GW->>DS: Rollen-/Tenant-Lookup (out-of-band)
    DS-->>GW: Rolle, tenant_id
    GW->>DB: SET app.current_tenant / SET ROLE (parametrisiert)
    GW->>LLM: Prompt (NL)
    LLM-->>GW: generiertes SQL
    GW->>DB: SQL ausführen
    DB-->>GW: nur Zeilen/Spalten gemäß RLS (USING/WITH CHECK)
    GW-->>U: Antwort
```

> **Sicherheitskern:** Selbst wenn das LLM (per Jailbreak) `SELECT * FROM orders`
> oder `UPDATE … SET role='admin'` erzeugt, entscheidet die DB anhand der
> **propagierten LDAP/AD-Identität** — nicht anhand des Prompts —, welche Zeilen
> sichtbar/änderbar sind. Die Identität liegt damit **außerhalb der
> Angriffsfläche** des Modells.
>
> **Bedrohung an dieser Stelle:** Der kritische Punkt ist die Integrität der
> Propagation selbst — das Gateway darf die Session-Variablen ausschließlich aus
> der verifizierten Identität setzen, niemals aus Prompt- oder LLM-Inhalt
> (sonst „confused deputy"). Das wird im Threat-Model explizit festgehalten.
okm 
> **Warum zeigt das Diagramm NL-to-SQL (LLM erzeugt SQL)?** Bewusst: Die Arbeit
> untersucht den **Status quo** (D0–DC), in dem das LLM freies SQL generiert —
> genau das ist die zu messende Angriffsfläche, und DC-b beweist seinen Wert
> *gerade* gegen bösartig erzeugtes SQL. Die Identitäts-Propagation (LDAP/AD →
> Session → RLS) ist **nicht** an NL-to-SQL gebunden: Bei **I6** (§5.3) gilt sie
> identisch, nur tritt an die Stelle von „generiertes SQL" ein „Template-Name +
> Parameter". Die LDAP→Session→RLS-Kette bleibt unverändert.

### 5.3 I6 — Eingeschränkte Tool-Schnittstelle (parametrisierte Templates)

**Doppelte Rolle:**

1. **Im Experiment — obere Vergleichsgrenze („Decke").** Statt freiem SQL nur
   geprüfte, parametrisierte Query-Templates / Stored Procedures; das LLM füllt
   ausschließlich Parameter. Dadurch entfällt **LLM05 konstruktionsbedingt** —
   das Modell kann keine beliebigen Statements mehr erzeugen.

2. **Als empfohlene Produktivarchitektur (gelockt).** Würde die in dieser Arbeit
   gebaute Idee real im Unternehmen eingesetzt, **muss** sie als I6 implementiert
   werden. Dann **entfällt freies NL-to-SQL vollständig** — was
   IT-sicherheitstechnisch überlegen ist:
   - keine SQL-Injection-Oberfläche durch das Modell,
   - jede mögliche Operation ist vorab definiert, geprüft und auditierbar,
     statt erst zur Laufzeit generiert,
   - das LLM degradiert vom „SQL-Autor" zum „Intent-/Parameter-Lieferanten".

> **Framing in der Arbeit:** NL-to-SQL (D0–DC) ist der untersuchte *Status quo*
> mit voller Angriffsfläche; I6 ist die **architektonische Konsequenz** der
> Befunde — die Empfehlung, die die Angriffsklasse LLM05 prinzipiell eliminiert.
> Im Experiment dient I6 als Referenz-Obergrenze, nicht als gleichwertiger
> NL-to-SQL-Messlayer (sonst würde die Natur des Systems verändert und der
> Vergleich verzerrt).

### 5.4 Optionale Härtung & Assurance (Ausblick / Diskussion)

| ID | Maßnahme | Zweck |
|----|----------|-------|
| **I5** | CHECK-Constraints / Trigger (z. B. „`orders.total` darf nach Zahlung nicht sinken"), `audit_log` append-only | deterministische Geschäftsregel-Integrität gegen W3/W5 |
| **I8** | Row-Caps / `statement_timeout` / `LIMIT`-Enforcement | gegen Massen-Exfiltration (LLM10-Aspekt) |
| **I9** | Dry-Run + Human-Approval für Hochrisiko-Writes (Transaktion, Diff zeigen, dann `COMMIT`) | **Assurance**: Nutzer sieht *was* geändert würde, bevor es passiert |

---

## 6. Auflösung des Hypothesen-Widerspruchs (Problem A)

**Alt (brainstorm2.md, Caveat):** „Gegen reinen Datenabfluss (LLM02) hilft
Least-Privilege wenig — dort sind A/B notwendig." — galt für DC = *Read-Only*.

**Neu:** DC ist jetzt **identitätsgebundene RLS + Masking** (DC-a/b/c). Damit
verteidigt DC **deterministisch**:
- Cross-Tenant-Read R1 (LLM02) — via RLS `USING`,
- Cross-Tenant-/Self-Write W1/W3, Escalation W2, Finanzbetrug W5 (LLM06) — via
  RLS `WITH CHECK` + Grants,
- Destruktiv W4 (LLM05/06) — via Grants (kein `DROP`/DDL),
- Column-Read R3 (LLM02) — via Masking.

**Korrigierte Hypothesen-Aussage:**

> DC (RLS + Grants + Masking) verteidigt Cross-Tenant-Zugriffe auf **Zeilen- und
> Spaltenebene deterministisch** — das deckt den **Großteil von LLM02** (R1–R3)
> **und ganz LLM06** (W1–W5) ab. Für **DA/DB** bleibt nur der Rest, den
> Infrastruktur prinzipiell nicht greifen kann: Exfiltration **innerhalb legitim
> lesbarer Zeilen** (paraphrasiertes Vorlesen erlaubter Daten) und die
> Text-Erkennung von Stored-Injection-Payloads (S1).

Damit wird **H3c schärfer und stärker**: Die deterministische Schicht deckt mehr
ab als ursprünglich angenommen; der verbleibende Zuständigkeitsbereich der
probabilistischen Layer ist präzise abgegrenzt (Spalten-/Paraphrase-Leak + S1).

### Aktualisierte Hypothesen (Ersatz für H3a/H3c)

- **H3a′:** DC-b (RLS USING+WITH CHECK) liefert den größten marginalen
  ASR-Rückgang über *alle* Cross-Tenant-Ziele (G-R1, G-W1, G-W2), während DA/DB
  dort schwächer und varianzbehaftet wirken.
- **H3b′:** DC erzeugt dabei geringeren Latenz-Mehraufwand als DB (kein zweiter
  Modell-Inferenzaufruf).
- **H3c′ (Kernaussage):** Deterministische DB-Härtung bietet ein besseres
  Sicherheits-/Kosten-Verhältnis als probabilistische LLM-Guardrails — für
  *alle* über die Berechtigungsmatrix abbildbaren Read/Write-Cross-Tenant-Ziele.
  A/B bleiben notwendig nur für Intra-Row-Exfiltration und S1-Texterkennung.

---

## 7. Experiment-Matrix (Konfiguration × Ziel)

Konfigurationen (inkrementell): **D0** · **DA** · **DB** · **DC-a** · **DC-b** ·
**DC-c** · **D++ (DA+DB+DC-a+DC-b+DC-c)** · **I6 (Referenz-Obergrenze)**.

Ziele: **G-R1 · G-R2 · G-W1 · G-W2 · G-W3 · G-S1**.

Je Zelle: n Wiederholungen → ASR (Mittelwert ± Streuung), zusätzlich
False-Positive-Rate auf dem Legitim-Anfragen-Set.

Erwartungsbild (qualitativ, zu verifizieren):

| Ziel | DA/DB | DC | I6 |
|------|:--:|:--:|:--:|
| G-R1 Cross-Tenant-Read | teilweise | **0 (DC-b)** | 0 |
| G-R2 Column-Read | teilweise | **0 (DC-c)** | 0 |
| G-W1 Unauth. Write | schwach | **0 (DC-b)** | 0 |
| G-W2 Escalation | schwach | **0 (DC-a/b)** | 0 |
| G-W3 Destruktiv | schwach | **0 (DC-a)** | 0 |
| G-S1 Stored Injection | **Hauptzuständigkeit DA/DB** | wirkt nur, wenn Aktion DB trifft | reduziert (kein freies SQL) |

> Lesart: DC fährt die Cross-Tenant-Ziele deterministisch auf ~0; der bleibende
> Wert von DA/DB zeigt sich v. a. bei **G-S1** und bei Intra-Row-Exfiltration.

---

## 8. Assurance — „Woher weiß der Nutzer, dass die Abwehr greift?"

- **Probabilistische Layer (DA/DB):** nur Statistik („hält in X %") — ein
  erfolgreicher Jailbreak genügt; Skepsis berechtigt.
- **Deterministische Layer (DC, I6, I5):** strukturelle, **beweisbare** Garantie.
  Die DB gibt fremde Zeilen physisch nicht heraus und akzeptiert verbotene Writes
  nicht — unabhängig vom LLM-Output, auf einer Ebene unterhalb des Modells.
- **Externe Prüfbarkeit:** Der Beweis ist der deterministische Layer selbst
  (RLS-Policies, Grants, Templates sind statisch lesbar/zertifizierbar), **nicht**
  eine vom System erzeugte Anzeige. Provenance-/Audit-Anzeige (welche Tabellen/
  Tenants berührt wurden) ist eine *Usability-Hilfe*, kein Beweis — ein
  kompromittiertes System könnte sie fälschen.
- **I9 (Dry-Run/Approval)** macht Hochrisiko-Writes für den Nutzer sichtbar,
  bevor sie wirken — anschaulicher Vertrauensbaustein.

---

## 9. Bezug zu den Forschungsfragen

- **FF1 (Wirksamkeit):** Berechtigungsmatrix (§2) definiert „erfolgreicher
  Angriff" eindeutig (Read- *und* Write-Verletzung) → präzises ASR je Ziel/Layer.
- **FF2 (Kosten):** inkrementelle Latenz/Energie je Layer; DC erwartet günstig,
  DB teuer (zweiter Modell-Call).
- **FF3 (Architektur vs. Modell):** DC (deterministisch) vs. DA/DB
  (probabilistisch) — Kernachse; I6 als architektonische Konsequenz/Obergrenze.

---

## 10. Offene Punkte / nächste Schritte

- [ ] DDL final: Schema + RLS-Policies (`USING` **und** `WITH CHECK`) +
      Spalten-Grants/Views + Canary-Datensätze pro Sensitivitätsstufe.
- [ ] Identitäts-Propagation spezifizieren: LDAP/AD-Lookup → Gateway →
      `SET app.current_user / app.current_tenant` → RLS.
- [ ] I6-Template-Katalog definieren (welche parametrisierten Operationen je
      Rolle) — zugleich die Spezifikation der Produktivarchitektur.
- [ ] Legitim-Anfragen-Set (Read + Write) für False-Positive-Rate / Usability.
- [ ] Oracles je Ziel implementieren (Canary-Match, State-Diff für Writes,
      DB-Log für DDL/DML), korreliert über Trace-ID.
- [ ] Statistik: n Wiederholungen, Signifikanztests für H1a/H3a′.
- [ ] `bedrohungsmodell.md` & `brainstorm2.md` an diese Fassung angleichen
      (Hypothesen H3a/H3c → H3a′/H3c′, Schreib-Angriffe, DC-Stufen).
- [ ] Folien aktualisieren (Schreib-Angriffe, DC-Stufen, I6 als Empfehlung).
- [x] OWASP-Bezeichnungen final gegen `LLMAll_en-US_FINAL` verifiziert (v2.0,
      offizielle Titel LLM01/02/05/06:2025 bestätigt).
