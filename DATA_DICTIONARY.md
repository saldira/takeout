# Data dictionary

Every CSV under `tables/` is one of these reports. The header row holds the
column ids below, in this order when every column is present. Amounts are decimal
strings with a dot; dates are ISO 8601 (YYYY-MM-DD); an empty cell is no value.

## `journal` — Journal / Journal

| column | meaning | type |
|---|---|---|
| `entry_id` | Entry / Buchung | Int |
| `booking_date` | Booking date / Buchungsdatum | Date |
| `value_date` | Value date / Valuta | Date |
| `narrative` | Narrative / Buchungstext | Text |
| `account_number` | Account number / Kontonummer | Text |
| `account_name` | Account name / Kontobezeichnung | Text |
| `debit` | Debit / Soll | Debit |
| `credit` | Credit / Haben | Credit |
| `currency` | Currency / Währung | Text |
| `functional_amount` | Functional amount / Betrag (Buchwährung) | Decimal |
| `functional_currency` | Functional currency / Buchwährung | Text |
| `amount` | Amount / Betrag | Decimal |
| `account_id` | Account id / Konto-ID | Int |
| `fx_rate` | FX rate / Kurs | Decimal |
| `fx_source` | FX source / Kursquelle | Text |
| `reverses` | Reverses / Storniert | Int |
| `reversed_by` | Reversed by / Storniert durch | Int |
| `dimensions` | Dimensions / Dimensionen | Dimensions |

## `account_statement` — Account statement / Kontoauszug

| column | meaning | type |
|---|---|---|
| `account_number` | Account number / Kontonummer | Text |
| `account_name` | Account name / Kontobezeichnung | Text |
| `entry_id` | Entry / Buchung | Int |
| `booking_date` | Booking date / Buchungsdatum | Date |
| `value_date` | Value date / Valuta | Date |
| `narrative` | Narrative / Buchungstext | Text |
| `counter_account` | Counter account / Gegenkonto | Text |
| `counter_account_name` | Counter account name / Gegenkonto-Bezeichnung | Text |
| `debit` | Debit / Soll | Debit |
| `credit` | Credit / Haben | Credit |
| `currency` | Currency / Währung | Text |
| `balance` | Balance / Saldo | Decimal |
| `amount` | Amount / Betrag | Decimal |
| `account_id` | Account id / Konto-ID | Int |
| `original_amount` | Original amount / Betrag (Originalwährung) | Decimal |
| `original_currency` | Original currency / Originalwährung | Text |
| `original_balance` | Original balance / Saldo (Originalwährung) | Decimal |
| `fx_rate` | FX rate / Kurs | Decimal |

## `trial_balance` — Trial balance / Saldenliste

| column | meaning | type |
|---|---|---|
| `number` | Account number / Kontonummer | Text |
| `name` | Account name / Kontobezeichnung | Text |
| `balance` | Balance / Saldo | Decimal |
| `currency` | Currency / Währung | Text |
| `account_id` | Account id / Konto-ID | Int |
| `debit` | Debit / Soll | Debit |
| `credit` | Credit / Haben | Credit |
| `original_balance` | Original balance / Saldo (Originalwährung) | Decimal |
| `original_currency` | Original currency / Originalwährung | Text |

## `ar_aging` — AR aging / Fälligkeitsliste Debitoren

| column | meaning | type |
|---|---|---|
| `number` | Document / Beleg | Text |
| `party_code` | Party code / Partnernummer | Text |
| `party_name` | Party name / Partnername | Text |
| `party_id` | Party id / Partner-ID | Int |
| `due_date` | Due date / Fällig am | Date |
| `days_overdue` | Days overdue / Tage überfällig | Int |
| `bucket` | Bucket / Fälligkeitsband | Int |
| `remaining` | Remaining / Offen | Decimal |
| `currency` | Currency / Währung | Text |

## `ap_aging` — AP aging / Fälligkeitsliste Kreditoren

| column | meaning | type |
|---|---|---|
| `number` | Document / Beleg | Text |
| `party_code` | Party code / Partnernummer | Text |
| `party_name` | Party name / Partnername | Text |
| `party_id` | Party id / Partner-ID | Int |
| `due_date` | Due date / Fällig am | Date |
| `days_overdue` | Days overdue / Tage überfällig | Int |
| `bucket` | Bucket / Fälligkeitsband | Int |
| `remaining` | Remaining / Offen | Decimal |
| `currency` | Currency / Währung | Text |

## `open_items` — Open items / Offene Posten

| column | meaning | type |
|---|---|---|
| `open_item_id` | Open item / Offener Posten | Int |
| `number` | Document / Beleg | Text |
| `party_code` | Party code / Partnernummer | Text |
| `party_name` | Party name / Partnername | Text |
| `party_id` | Party id / Partner-ID | Int |
| `account_number` | Account number / Kontonummer | Text |
| `account_name` | Account name / Kontobezeichnung | Text |
| `account_id` | Account id / Konto-ID | Int |
| `status` | Status / Status | Text |
| `due_date` | Due date / Fällig am | Date |
| `original_amount` | Original amount / Betrag (Originalwährung) | Decimal |
| `original_currency` | Original currency / Originalwährung | Text |
| `remaining` | Remaining / Offen | Decimal |
| `remaining_currency` | Remaining currency / Währung (offen) | Text |
| `booking_rate` | Booking rate / Buchungskurs | Decimal |

## `documents` — Documents / Belege

| column | meaning | type |
|---|---|---|
| `number` | Document / Beleg | Text |
| `booking_date` | Booking date / Buchungsdatum | Date |
| `due_date` | Due date / Fällig am | Date |
| `party_code` | Party code / Partnernummer | Text |
| `party_name` | Party name / Partnername | Text |
| `party_id` | Party id / Partner-ID | Int |
| `currency` | Currency / Währung | Text |
| `net` | Net / Netto | Decimal |
| `tax` | VAT / MWST | Decimal |
| `gross` | Gross / Brutto | Decimal |
| `remaining` | Remaining / Offen | Decimal |
| `settled_on` | Settled on / Ausgeglichen am | Date |
| `external_ref` | Reference / Referenz | Text |
| `entry_id` | Entry / Buchung | Int |
| `open_item_id` | Open item / Offener Posten | Int |
| `reverses` | Reverses / Storniert | Text |
| `reversed_by` | Reversed by / Storniert durch | Text |
| `credits` | Credits / Gutschrift für | Text |
| `credited_by` | Credited by / Gutgeschrieben durch | Text |

## `dispositions` — Bank dispositions / Bankverbuchungen

| column | meaning | type |
|---|---|---|
| `statement_id` | Statement / Kontoauszug | Text |
| `entry_ref` | Statement line / Bewegung | Text |
| `disposition` | Disposition / Verbuchung | Text |
| `amount` | Amount / Betrag | Decimal |
| `currency` | Currency / Währung | Text |
| `decided_by` | Decided by / Entschieden von | Text |
| `decided_at` | Decided at / Entschieden am | Date |
| `reversed` | Reversed / Storniert | Bool |
| `reason` | Reason / Grund | Text |
| `note` | Note / Notiz | Text |
| `counterparty` | Counterparty / Gegenpartei | Text |

## `mwst_form` — VAT return / MWST-Abrechnung

| column | meaning | type |
|---|---|---|
| `section` | Section / Abschnitt | Text |
| `reference` | Ref. / Ziffer | Int |
| `label` | Description / Bezeichnung | Text |
| `umsatz` | Turnover / Umsatz | Decimal |
| `steuer` | Tax / Steuer | Decimal |
| `currency` | Currency / Währung | Text |

## `parties` — Parties / Geschäftspartner

| column | meaning | type |
|---|---|---|
| `party_id` | Party id / Partner-ID | Int |
| `code` | Code / Nummer | Text |
| `name` | Name / Name | Text |
| `active` | Active / Aktiv | Bool |
| `currency` | Currency / Währung | Text |
| `vat_number` | VAT number / MWST-Nr. | Text |
| `street` | Street / Strasse | Text |
| `building` | Building / Hausnummer | Text |
| `postal_code` | Postal code / PLZ | Text |
| `town` | Town / Ort | Text |
| `country` | Country / Land | Text |
| `iban` | IBAN / IBAN | Text |
| `further_ibans` | Further IBANs / Weitere IBAN | FurtherIbans |
| `language` | Language / Sprache | Text |
| `tax_status` | Tax status / Steuerstatus | Text |
| `payment_terms` | Payment terms / Zahlungskondition | Text |

## `audit_log` — Audit log / Änderungsprotokoll

| column | meaning | type |
|---|---|---|
| `id` | Log no. / Protokoll-Nr. | Int |
| `recorded_at` | Recorded at / Zeitpunkt | Text |
| `principal` | Person / Person | Text |
| `book` | Book / Buch | Text |
| `category` | Category / Bereich | Text |
| `method` | Action / Vorgang | Text |
| `payload` | Content / Inhalt | Text |
| `request_id` | Request id / Anfrage-ID | Text |

## `items` — Items / Artikel

| column | meaning | type |
|---|---|---|
| `item_id` | Item id / Artikel-ID | Int |
| `code` | Code / Nummer | Text |
| `name` | Name / Name | Text |
| `kind` | Kind / Art | Text |
| `unit` | Unit / Einheit | Text |
| `unit_price` | Unit price / Einzelpreis | Decimal |
| `currency` | Currency / Währung | Text |
| `revenue_account` | Revenue account / Ertragskonto | Text |
| `expense_account` | Expense account / Aufwandkonto | Text |
| `default_tax_code` | Default tax code / Standard-Steuercode | Text |
| `price_period` | Price period / Preisperiode | Text |
| `active` | Active / Aktiv | Bool |

## `tax_codes` — Tax codes / Steuercodes

| column | meaning | type |
|---|---|---|
| `tax_code_id` | Tax code id / Steuercode-ID | Int |
| `code` | Code / Nummer | Text |
| `label` | Label / Bezeichnung | Text |
| `direction` | Direction / Richtung | Text |
| `treatment` | Treatment / Behandlung | Text |
| `account` | Account / Konto | Text |
| `archived` | Archived / Archiviert | Bool |

## `price_lists` — Price lists / Preislisten

| column | meaning | type |
|---|---|---|
| `price_list_id` | Id / ID | Int |
| `code` | Code / Nummer | Text |
| `name` | Name / Name | Text |
| `currency` | Currency / Währung | Text |
| `active` | Active / Aktiv | Bool |

## `payment_terms` — Payment terms / Zahlungsbedingungen

| column | meaning | type |
|---|---|---|
| `payment_terms_id` | Id / ID | Int |
| `code` | Code / Nummer | Text |
| `name` | Name / Name | Text |
| `net_days` | Net days / Netto-Tage | Int |
| `active` | Active / Aktiv | Bool |

## `numbering_schemes` — Numbering schemes / Nummernkreise

| column | meaning | type |
|---|---|---|
| `target` | Target / Ziel | Text |
| `scope` | Scope / Geltungsbereich | Text |
| `reset` | Reset / Zurücksetzung | Text |
| `start` | Start / Beginn | Int |
| `next_seq` | Next sequence / Nächste Nummer | Int |
| `next_code` | Next code / Nächster Code | Text |
| `configured` | Configured / Konfiguriert | Bool |

## `custom_fields` — Custom fields / Benutzerdefinierte Felder

| column | meaning | type |
|---|---|---|
| `field_id` | Id / ID | Int |
| `entity` | Entity / Objekt | Text |
| `key` | Key / Schlüssel | Text |
| `label` | Label / Bezeichnung | Text |
| `kind` | Kind / Art | Text |
| `required` | Required / Pflichtfeld | Bool |
| `active` | Active / Aktiv | Bool |

## `distribution_keys` — Distribution keys / Verteilschlüssel

| column | meaning | type |
|---|---|---|
| `key_id` | Id / ID | Int |
| `code` | Code / Nummer | Text |
| `name` | Name / Name | Text |
| `dimension_code` | Dimension / Dimension | Text |
| `active` | Active / Aktiv | Bool |

## `member_grants` — Members / Mitglieder

| column | meaning | type |
|---|---|---|
| `principal` | Principal / Person | Text |
| `roles` | Roles / Rollen | Words |
| `sponsor` | Sponsor / Vergeben von | Text |
| `agent` | Agent / Agent | Bool |
| `agent_mode` | Agent mode / Agentenmodus | Text |

## `bank_accounts` — Bank accounts / Bankkonten

| column | meaning | type |
|---|---|---|
| `id` | Id / ID | Int |
| `label` | Label / Bezeichnung | Text |
| `iban` | IBAN / IBAN | Text |
| `currency` | Currency / Währung | Text |
| `gl_account` | GL account / Hauptbuchkonto | Int |
| `is_default` | Default / Standard | Bool |
| `use_for_qr` | Used for QR-bills / Für QR-Rechnung | Bool |
| `bic` | BIC / BIC | Text |
| `bank_name` | Bank / Bank | Text |
| `archived` | Archived / Archiviert | Bool |

## `bank_statements` — Bank statements / Kontoauszüge

| column | meaning | type |
|---|---|---|
| `statement_id` | Statement / Kontoauszug | Text |
| `bank_account` | Bank account / Bankkonto | Int |
| `from` | From / Von | Date |
| `to` | To / Bis | Date |
| `entry_count` | Entries / Buchungen | Int |
| `disposed_lines` | Disposed lines / Verbuchte Zeilen | Int |
| `camt_sha256` | camt SHA-256 / camt-Prüfsumme (SHA-256) | Text |

## `vat_returns` — VAT returns / MWST-Abrechnungen

| column | meaning | type |
|---|---|---|
| `seq` | Sequence / Laufnummer | Int |
| `from` | From / Von | Date |
| `to` | To / Bis | Date |
| `kind` | Kind / Art | Text |
| `method` | Method / Methode | Text |
| `basis` | Basis / Abrechnungsart | Text |
| `net_payable` | Net payable / Zahllast | Decimal |

## `fiscal_years` — Fiscal years / Geschäftsjahre

| column | meaning | type |
|---|---|---|
| `label` | Label / Bezeichnung | Text |
| `start` | Start / Beginn | Date |
| `end` | End / Ende | Date |
| `closed` | Closed / Abgeschlossen | Bool |
| `locked` | Locked / Gesperrt | Bool |

## `periods` — Periods / Perioden

| column | meaning | type |
|---|---|---|
| `period_id` | Period / Periode | Int |
| `start` | Start / Beginn | Date |
| `end` | End / Ende | Date |
| `status` | Status / Status | Text |

## `dimensions` — Dimensions / Dimensionen

| column | meaning | type |
|---|---|---|
| `dimension_id` | Id / ID | Int |
| `code` | Code / Nummer | Text |
| `name` | Name / Name | Text |
| `kind` | Kind / Art | Text |
| `description` | Description / Beschreibung | Text |

## `abos` — Subscriptions / Abos

| column | meaning | type |
|---|---|---|
| `abo_id` | Id / ID | Int |
| `name` | Name / Name | Text |
| `party_id` | Party id / Partner-ID | Int |
| `currency` | Currency / Währung | Text |
| `start` | Start / Beginn | Date |
| `end` | End / Ende | Date |
| `narrative` | Narrative / Buchungstext | Text |
| `archived` | Archived / Archiviert | Bool |

## `quotes` — Quotes / Offerten

| column | meaning | type |
|---|---|---|
| `number` | Document / Beleg | Text |
| `party_id` | Party id / Partner-ID | Int |
| `issued_on` | Issued on / Ausgestellt am | Date |
| `valid_until` | Valid until / Gültig bis | Date |
| `currency` | Currency / Währung | Text |
| `net` | Net / Netto | Decimal |
| `gross` | Gross / Brutto | Decimal |
| `status` | Status / Status | Text |
| `version` | Version / Version | Int |
| `narrative` | Narrative / Buchungstext | Text |

## `orders` — Orders / Aufträge

| column | meaning | type |
|---|---|---|
| `number` | Document / Beleg | Text |
| `party_id` | Party id / Partner-ID | Int |
| `issued_on` | Issued on / Ausgestellt am | Date |
| `currency` | Currency / Währung | Text |
| `net` | Net / Netto | Decimal |
| `gross` | Gross / Brutto | Decimal |
| `status` | Status / Status | Text |
| `version` | Version / Version | Int |
| `narrative` | Narrative / Buchungstext | Text |

## `allocation_runs` — Allocation runs / Umlageläufe

| column | meaning | type |
|---|---|---|
| `run_id` | Run / Lauf | Int |
| `from` | From / Von | Date |
| `to` | To / Bis | Date |
| `rules_digest` | Rules digest / Regel-Prüfsumme | Text |
| `rules_changed` | Rules changed / Regeln geändert | Bool |

## `bank_transactions` — Bank transactions / Bankbewegungen

| column | meaning | type |
|---|---|---|
| `transaction_id` | Id / ID | Int |
| `booking_date` | Booking date / Buchungsdatum | Date |
| `value_date` | Value date / Valuta | Date |
| `amount` | Amount / Betrag | Decimal |
| `currency` | Currency / Währung | Text |
| `counterparty` | Counterparty / Gegenpartei | Text |
| `reference` | Reference / Referenz | Text |
| `bank_reference` | Bank reference / Bankreferenz | Text |
| `status` | Status / Status | Text |
| `disposition` | Disposition / Verbuchung | Text |

## `accounts` — Chart of accounts / Kontenplan

| column | meaning | type |
|---|---|---|
| `number` | Account number / Kontonummer | Text |
| `name` | Account name / Kontobezeichnung | Text |
| `class` | Class / Kontoart | Text |
| `natural_currency` | Account currency / Kontowährung | Text |
| `monetary` | Monetary / Monetär | Bool |
| `archived` | Archived / Archiviert | Bool |
| `account_id` | Account id / Konto-ID | Int |
