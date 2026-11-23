# Dashboard UI, part 2: the shell and the pages

Approved by the owner on 2026-11-22 ("Yeah approved", for the second pass of [proposal.md](proposal.md) with its
recommended answers). Built in this branch.

## How it is built

| Piece | Where |
| --- | --- |
| The shell: one table of places (path, name, icon, shortcut, permission) that the navigation, the header's search and the shortcuts help all read; counts of what waits; theme; version | `web/ui.rs`, `templates/base.html` |
| Pages outside the shell: sign-in, code, first run | `templates/alone.html` |
| Colors as tokens, each defined once for both themes with `light-dark()`; blocks lay themselves out by container queries | `static/app.css` |
| Menus, dialogs, search as you type, palette, shortcuts, the notice after an update | `static/app.js` |
| Form checks, fields that depend on a choice, show and copy buttons | `static/forms.js` |
| Icons: the Material Symbols in use, inlined | `web/icons.rs` (Apache-2.0) |
| The mark, which is the favicon too | `static/icon.svg` |

- **Dialogs have addresses** (`/users?add=user`, `/users?edit=<id>`, `/patching?confirm=...`). The hub draws the page with
  the dialog open; the script makes it modal, and opens it from a link without leaving the page. Closing it, or a browser
  without script, goes back to the list by a link. A refused form returns in its dialog.
- **Errors** (`status()`) are drawn in the shell for someone signed in: the gate redraws them.
- **Theme**: `POST /theme` sets the cookie `rh_theme`; the page is drawn with it, so there is no flash.
- **Returning**: a page asked for without a session, and what needed a step-up, is remembered in the cookie `rh_next` for
  ten minutes (local paths only) and returned to once.
- **Updates**: `GET /version` gives the version and a build id (a hash of the version and the hub's own files). A page
  that was open before says it was updated, and never reloads by itself. The hub's own files are cached 5 minutes
  instead of a day, so a page after an update isn't drawn with the old styles.
- **New addresses**: `/users`, `/find`, `/about`, `/shortcuts`, `/version`, `/theme`, `/static/app.js`,
  `/static/icon.svg`. Every address that existed keeps working, and every form posts where it did.

## Found and fixed on the way

- htmx injects a style of its own, which the content security policy blocks with an error on every page. It is turned off
  (`htmx-config`).
- Every page's links were its own list; Settings, Add and Account couldn't be reached from most. One table now.
- Accepting a host key or confirming a guest returned to the overview; it returns to the machine.
- A window's machine was shown by its id.

## Tests, seen failing and passing

| Test | Failed before | Passes |
| --- | --- | --- |
| `web::tests::shell::*` (16, then 2 more and additions to 2) | 2026-11-22, 16 of 16, then each | 2026-11-22 |
| In `a_window_is_picked_from_day_time_and_length`, the machine's name | 2026-11-22 | 2026-11-22 |
| `pages_for_measuring` | Not a rule of its own: it draws every page and dialog for the checks below | 2026-11-22 |

Existing tests changed only where the approved design changed what they read: text is read tolerantly of markup
(`plain`, `cells`) with the same assertions; users and devices are looked for on `/users`; a rejection and an appliance
form are looked for in their dialogs; new passwords are typed twice; the escaping test counts scripts that aren't the
hub's own instead of expecting exactly one. The window form's old fields gave way to the new ones; a rule posted as text
(`rrule`) is still taken. Clients that read pages (`tests/live`, `tests/it`) read the new markup; they compile and
haven't been run here.

## Checks in a browser

Chromium, the real pages with real styles and scripts, written out by `pages_for_measuring`:

| Check | Result |
| --- | --- |
| [measure.js](measure.js): 44 pages and dialogs (and the account menu and drawer) at 19 widths from 320 to 2560px, 865 screens, 14,345 controls: nothing past an edge, cut off, unlabeled, taller than the screen, under 44px on a phone or 40px otherwise, under 16px in a phone's field, or a short word split over lines | 0 |
| The same with scripts off | 0 |
| axe-core 4.13 ([axe.js](axe.js)), WCAG 2.2 A and AA and best practices, 44 pages, light and dark, 1280 and 390px | 0 |
| Contrast of every token pair in both themes | a Rust test, 4.5:1 or better |
| Save off until a change, Undo, Esc on unsaved changes asking with the safe choice focused, focus on open | as designed |

The first runs found, and the fixes are in: lists in narrow columns of wide screens that didn't fold (they fold by their
own width now), a brand link too narrow to touch, a 13px field, short words split in narrow columns, and a search link without a name on phones.

### On a running hub

A throwaway hub on this computer (built from this branch, first run completed, no machines), in the desktop app's
Chromium, on 2026-11-23:

| Walked | Result |
| --- | --- |
| A page asked for without a session (`/audit?q=sign`), then sign-in with a password and an authenticator code | Returned to that page with its search |
| Every page in the navigation, every dialog address, `/find`, `/step-up` and an unknown address | Each answered with its heading (the unknown one 404); no content security policy errors in the console |
| Add a user from its button | Opened as a modal without leaving the page, focus in the first field |
| The same form refused by the hub (a name that is taken, passwords that differ) | Returned in its dialog with both problems listed (the taken name only after the fix below) |
| Ctrl K, typing, arrow and Enter | The palette found Audit and opened it |
| `?`, Esc, `g i` | Shortcuts shown, closed, Incidents opened |
| Theme from the account menu | Light and dark, on the same page, without a flash |
| 375px: the drawer, Esc, a long dialog in dark | The drawer opens and closes; the dialog fits the screen and scrolls inside |

Found and fixed (tests first, `add_user_shows_every_problem_and_the_new_key_has_a_qr_code` and
`counts_and_offers_are_worded_right`): a taken user name was said only once every other field was right; the phone's menu
button said "1 open incidents, 0 approvals waiting"; an empty machine list offered "Add machine", unlike the button
above it. (That link still goes to the Add page, as a test of the overview expects, and is shown to viewers too, who
can't add a machine; left as it was.)

Not walked there: the step-up return and the live vitals, which need a machine (their tests cover them).

## Deviations and limits

- The overview's machine list has CPU and memory, not disk: a machine has several disks and the page has no rule for
  which to show. The worst disk is the Site page's in 7.7.1 and is left to that task.
- The proposal named an incident filter; the two lists (open, resolved) stay, with one search, because live tests and
  people read them by those names.
- There is no way yet to delete a policy or a window (Policy has no such command), so their lists have none.
- The Add page posts operator and peer invites straight from a button, as before: they have no fields.
- Not checked: Safari and Firefox, and real phones.
- A hub makes a new certificate each time it starts, so a browser warns again after every restart. That isn't
  changed here.
