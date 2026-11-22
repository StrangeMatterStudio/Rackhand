# Dashboard UI, part 2: proposal

Status: Proposed, waiting on the owner. Nothing here is built yet except where it says so.

The owner asked for the dashboard to follow the studio's UI standards (the pages UI and Design System; Layout,
Navigation and Hotkeys; Interface Design Principles; Health, About and Updates; Testing and Verification; and the UI
parts of Authentication and the Security Checklist), read on 2026-11-22. This is a read of the templates, styles and
page code. Example pages with made-up data are with the owner.

## What already meets them

- Light and dark follow the system. System fonts, vendored assets, nothing loaded from elsewhere.
- Strict content security policy with no inline script or style; CSRF on every state-changing route; every page works
  without script.
- First run redirects every page, is atomic and rate limited, and asks for a code before it turns the second factor on.
- Since part 1: errors beside their fields with everything kept, a show toggle on every password, `autocomplete` as the
  standards ask, QR code plus key with a copy button, secrets shown once with a copy button.

## Gaps in binding rules

| Rule | Today (evidence: repo) | Proposed |
| --- | --- | --- |
| One app shell: mark top left, account top right, search, sidebar; a page named as in the navigation | `base.html` has a top bar; each template lists its own links, so Settings, Add and Account can't be reached from most pages | One shell in `base.html`, from one table of pages filtered by role |
| Theme choice System, Light, Dark in the account menu | None | Three icon buttons; kept in a cookie per browser, set by the hub, so there is no flash and no script needed |
| Google Material Symbols, inlined | No icons | The paths used, inlined from a Rust table (Apache-2.0, with the license file) |
| A list informs and a dialog changes; one button per row | `settings.html` has a role picker and two buttons in each row; `patching.html` has its forms under its lists | View, Edit and Add dialogs, each with an address and drawn open by the hub, so they work without script |
| Every removal asks, with the safe choice focused | Disable, Revoke and Reject act at once | Confirmation dialogs with addresses |
| Search on lists that can grow | None | Machines, incidents, jobs, library, audit, users, devices, services, containers: a GET form the hub answers, filtered as typed with script |
| A choice shows only its own fields | SNMP version, and password or OIDC, show everything | Shown and hidden by script; all shown without |
| Three settings areas | One Settings page | Account, Users (with devices), System settings |
| Cards, stat tiles, key-value blocks, badges with a word, empty states that say what to do | Bare tables and paragraphs | As in the example pages |
| Tables stack on phones; no sideways scroll at 375px; 40px targets; visible focus | Tables overflow; small links; browser default focus | Stacked rows, 40px, one focus ring |
| Motion 0.12 to 0.3 s, expanding animates, none for hotkeys or reduced motion | None | One set of transitions, `data-instant`, the reduced-motion clamp |
| Hotkeys, the palette and `?` help from one table | None | `Ctrl+K`, `/`, `c`, `?`, `g` and a letter, `Esc`, `Ctrl+Enter` |
| About, the version in the interface, a notice after an update | The version is shown nowhere | About in the account menu, the version in the sidebar, a notice with Refresh, never an automatic reload |
| A new password is typed twice | Once, with a show toggle | Twice, with the toggle |
| Never lose someone's work | Fixed for refused forms in part 1; step-up and an expired session still lose the place | Discard question on dialogs; step-up and sign-in return to the page that asked |
| Both themes pass an accessibility check | None | See decision 4 |

## Gaps in proposed rules

| Rule | Today | Proposed |
| --- | --- | --- |
| Spacing from a 4px scale; the token names | Ad hoc values, six color tokens | The scale and the token names |
| Commands that aren't field edits have their own section | Mixed into the settings page | Own sections |

## Conflicts for the owner

1. The standards say the UI never refers to its repository. `0001-architecture` 7.3.12 and 7.3.4 have the Add page show
   install commands that download from the public releases. Recommended: keep the commands (they are a public download,
   not a link to source), and show the offline command, from the hub itself, first when the hub holds the files.
2. The standards' account rules (email sign-in, ten recovery codes, temporary passwords, Argon2id settings and pepper)
   differ from 7.7.2. They aren't UI and aren't part of this proposal.
3. The standard stack is Node with PostgreSQL, and its tests use Playwright. Rackhand is Rust with no Node, by design.

## Decisions for the owner

1. The mark: a rack drawer pulled out by its handle, in the squircle the other products use, or one the owner supplies.
2. Conflict 1 above.
3. The theme choice in a cookie per browser (recommended), or per account in the database.
4. Accessibility without Node: Rust tests for the contrast of every token pair in both themes, labels, headings,
   landmarks and target sizes; plus axe run by hand in a browser on every page in both themes, recorded here
   (recommended). Or Playwright in continuous integration only.
5. New passwords typed twice, on first run and for a new user.

## Proposed change to `0001-architecture/design.md` 7.7.1

"Every page uses one shell: header (mark, search, account menu), sidebar, main. Pages that list things inform; changes
happen in dialogs with addresses of their own, drawn open by the hub, so they work without script. Settings is three
areas: Account (everyone), Users and System settings (admins)." Paths that exist keep working.

## Page by page

| Page | Change |
| --- | --- |
| Overview | Stat tiles (machines by health, open incidents, approvals waiting, updates), a card per site, open incidents, machines with search |
| Site | Machines as a list with health badges and search |
| Machine | Key-value card, vitals card, incidents, updates, services, containers; the guest binding in a dialog; a silent probe as a banner |
| Incidents, incident | One list with an open or resolved filter and search; the incident as a key-value card and a timeline |
| Approvals | A card per approval with exactly what it binds, as now; Reject asks; the count in the sidebar |
| Jobs, job | List with search; steps as cards with exit code badges |
| Library, item | List with search and kind; opens for reading, Edit opens the editor with Save off until a change |
| Patching | Pending updates, policies and windows as lists; Add and Edit in dialogs |
| Add | Machine, appliance, invite and site as four choices, each in a dialog; commands with copy buttons; the recently added below |
| Account | Profile, authenticator, passkeys, theme |
| Users | Users and devices, each a list with search |
| System settings | Outside sources, git mirror, OIDC and notifiers as cards, each saving on its own |
| Audit | Chain status, search, the log |
| Sign-in, step-up, first run | One centered card |
| Errors, not found | In the shell, saying what to do next |

Pages the design has but the hub doesn't yet (Security, Peers and relays, the long charts) get their place in the
sidebar with their own plan tasks.

## Order of work, after approval

1. Tokens, shell, icons, theme, motion, shortcuts, About and the update notice, with tests that walk every page.
2. The list, dialog and confirmation kit, with the rules checked as tests on every page.
3. The pages, in the order above, each checked at 1200px and 375px, in light and dark, with script off, and by keyboard.
4. The accessibility record and the design wording.

Each step is its own commit with its tests first.
