# Dashboard UI, part 1: first run and the other forms

The owner went through first run on a real hub and found that fields didn't say what they need, errors came one at a
time and sometimes on a page of their own with the form lost, timezones were typed unchecked, and the authenticator had
no QR code and its 30-second code sat among the other fields. This part fixes that, and the same faults in every other
form.

## What changed

### One approach to forms

`crates/rackhand-hub/src/web/forms.rs`. A form is a table of fields (`Spec`): label, hint, kind, pattern with the
sentence said when it isn't met, lengths, choices. The page renders from it, the server checks from it, and
`static/forms.js` checks the same attributes as the form is filled in.

- Every problem comes back at once: a summary at the top that links to each field, and each problem beside its field
  (`aria-invalid`, `aria-describedby`). What was typed is kept.
- Secrets are never sent back to the browser. The ones that weren't what was wrong are held in memory (zeroized when
  dropped), for the same session or anonymous cookie and the same form, for 30 minutes and one try. The field then says
  "Kept from your last try".
- Forms carry `novalidate`: the browser's own bubbles show one error at a time. `required`, `pattern` and `minlength`
  stay as the rules the script reads.
- Without JavaScript everything still works; the server's answer says the same.
- A select replaces typing wherever there is a list: timezones (from the bundled database, preselected from the
  browser), machines, users, roles, SNMP versions.

### First run

Two steps, three pages: details, authenticator, recovery code.

1. `POST /first-run` takes the setup code, admin name, password, site, timezone and sources. Everything is checked
   together. A wrong setup code is one problem among the others (still 403, still counted against the source); an
   attempt over the limit is still 429. Both show the form as it was sent.
2. `GET` and `POST /first-run/second-factor`, open only once the details are accepted: a QR code, the key with a copy
   button, a link for an app on the same device, and the code. A wrong code shows the same key and QR code again, with
   the hub's clock. The details can be changed from here; the key stays.
3. The recovery code, once, as before. The same single batch with `InsertIfTableEmpty` makes the admin.

Between the steps the hub keeps a draft in memory for the browser's anonymous cookie: whether the setup code was right
(it isn't asked for again), the password's Argon2id hash, the details and the authenticator's key. It lasts an hour
after it was last used; at most 256 are kept, and those without the setup code go first. What was typed is remembered
only once the setup code was right. If a draft is gone (an hour, or a restarted hub), the second step's form carries
the details, so the first step comes back filled in and says that the setup code and password are needed again.

The key is no longer sent by the browser, so the signed form value (`csrf::sign`) is gone. The anonymous cookie lasts
12 hours instead of 1, so a page left open can still be sent.

### The other forms

| Page | Was | Is |
| --- | --- | --- |
| Add: machine, device invite | Bare page per error | On the form |
| Add: appliance, both halves | Bare page per error; credentials lost | On the driver's form; the credentials page stays after a failed first poll, secrets held |
| Add: SNMP | Asked for "SHA or SHA-256" and "AES"; the driver takes only `sha` and `aes`, so what the label said was refused | Version picked from a list; what it needs is said together |
| Settings: users | Bare page, first error only; new key without a QR code; the role list always showed "viewer" | On the form; QR code, key and copy button; each user's own role |
| Settings: last admin, devices | Bare page | On the Settings page |
| Settings: git mirror, OIDC | Bare page, first error only, input lost | On the form |
| Notifiers | Bare page, first error only, input lost | On the form |
| Notifiers: Send test | Its result was on a page that refreshed away at once | On the Notifiers page |
| Policies, windows | Bare page, first error only; the machine's id had to be typed | On the form; machine and timezone picked |
| Library | A draft that didn't validate, or a failed save: bare page | On the page, the text kept |
| Approvals, machine buttons, passkeys | Bare page | On the page |
| Sign-in | The name was lost; limits on a bare page; after 5 wrong codes back to the start without a word; a wrong code dropped the passkey button | Kept, said on the form |

### Cause of one complaint

The admin name's rule was in the page (`pattern="[a-z0-9._-]{1,64}"`), but browsers compile `pattern` with the `v` flag,
where a bare `-` at the end of a class is an error, and then check nothing. It is `\-` now, and a test looks for bare
ones on every page.

## Dependencies

- `qrcodegen` 1 (MIT, no dependencies): the QR code.
- `rqrr` 0.10 (MIT or Apache-2.0), tests only: reads the QR code back as an app would.

## Proposed wording for `0001-architecture/design.md`

For the owner to confirm; not applied in this branch.

7.7.1, the First run row: "Create the admin (name and password), name the site, pick its timezone and review outside
sources (7.8.5), with every problem shown at once; then, as a step of its own, the second factor (TOTP with a QR code,
or a passkey when the hub has a trusted certificate); then store the master-key recovery code, shown once."

7.7.1, after the table: "Forms show every problem at once, beside its field, and keep what was typed. Passwords and
other secrets are never sent back; the hub holds the ones typed into a refused form in memory for up to 30 minutes, for
that session's next try. First run's details wait for the second step in memory for up to an hour, with the password
hashed."

## Tests, seen failing and passing

| Test | Failed before | Passes |
| --- | --- | --- |
| `web::tests::first_run::*` (13) and the 4 existing first-run tests, moved to two steps | 2026-11-22, 17 of 17 | 2026-11-22 |
| `web::tests::forms::*` (12) | 2026-11-22, 12 of 12 | 2026-11-22 |
| `a_failed_test_message_stays_on_the_notifiers_page`, `wrong_codes_keep_the_step_and_the_last_one_says_why_it_ends`, `held_secrets_expire_and_work_once`, `the_rules_shown_are_the_rules_kept` | Written after their change; each failed with its change broken on purpose | 2026-11-22 |

The existing tests keep their assertions (setup codes 403 and 429, two first runs one admin, recovery code once, every
status code). Two things in them changed: their helpers do both steps, and the two-admins race now starts with both
browsers on the second step.

## Deviations and limits

- A session that has expired (2 hours idle) still redirects a sent form to sign-in, and what was typed is lost.
- Step-up still returns to the overview, not to what asked for it.
- An appliance or machine whose form was abandoned keeps its name (a `pending` row), so the same name is refused until
  that row is gone. That is the Registry's; it isn't changed here.
- The integration and live tiers' first-run clients are updated and compile; they haven't been run in this branch.
