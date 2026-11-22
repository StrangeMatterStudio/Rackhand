# Evidence

Run on 2026-11-22 with `cargo nextest run -p rackhand-hub`, trimmed to the result lines.

## Before: first run
```
FAIL [   6.094s] ( 1/17) rackhand-hub web::tests::first_run::all_problems_are_shown_together_beside_their_fields_with_the_input_kept
FAIL [   7.503s] ( 2/17) rackhand-hub web::tests::first_run::timezones_are_picked_from_the_known_list
FAIL [   8.125s] ( 3/17) rackhand-hub web::tests::first_run::an_accepted_setup_code_is_not_asked_for_again
FAIL [   8.125s] ( 4/17) rackhand-hub web::tests::first_run_setup_code_guessing_limited
FAIL [   8.125s] ( 5/17) rackhand-hub web::tests::first_run_shown_until_admin_exists
FAIL [   8.125s] ( 6/17) rackhand-hub web::tests::first_run::a_refused_change_of_details_is_not_finished_with_the_old_ones
FAIL [   8.125s] ( 7/17) rackhand-hub web::tests::first_run::every_field_says_what_it_needs_before_anything_goes_wrong
FAIL [   8.125s] ( 8/17) rackhand-hub web::tests::first_run::a_wrong_code_keeps_the_key_and_loses_nothing
FAIL [  24.750s] ( 9/17) rackhand-hub web::tests::first_run::the_second_factor_is_its_own_last_step_with_a_qr_code_and_the_key
FAIL [  24.772s] (10/17) rackhand-hub web::tests::first_run::the_second_step_belongs_to_the_browser_that_passed_the_first
FAIL [  24.772s] (11/17) rackhand-hub web::tests::post_without_csrf_token_is_403
FAIL [  24.772s] (12/17) rackhand-hub web::tests::first_run::the_details_can_be_changed_from_the_second_step
FAIL [  24.772s] (13/17) rackhand-hub web::tests::first_run::a_page_left_open_for_hours_can_still_be_sent
FAIL [  24.772s] (14/17) rackhand-hub web::tests::first_run::a_second_step_left_too_long_returns_to_filled_in_details
FAIL [  24.772s] (15/17) rackhand-hub web::tests::first_run::a_wrong_setup_code_keeps_the_form_and_names_every_other_problem
FAIL [  24.772s] (16/17) rackhand-hub web::tests::first_run_shows_recovery_code_once
FAIL [  24.773s] (17/17) rackhand-hub web::tests::first_run::an_attempt_over_the_limit_keeps_the_form
Summary [  24.774s] 17 tests run: 0 passed, 17 failed, 301 skipped
```

## Before: the other forms
```
FAIL [   7.944s] ( 1/12) rackhand-hub web::tests::forms::sign_in_keeps_the_name_and_says_what_to_do
FAIL [   8.240s] ( 2/12) rackhand-hub web::tests::forms::policies_and_windows_show_every_problem
FAIL [   8.253s] ( 3/12) rackhand-hub web::tests::forms::a_failed_first_poll_keeps_the_credentials_form
FAIL [   8.253s] ( 4/12) rackhand-hub web::tests::forms::settings_show_every_problem_on_the_form_that_was_sent
FAIL [   8.253s] ( 5/12) rackhand-hub web::tests::forms::no_form_relies_on_the_browsers_one_at_a_time_bubbles
FAIL [   8.253s] ( 6/12) rackhand-hub web::tests::forms::add_machine_shows_every_problem_on_its_form
FAIL [   8.253s] ( 7/12) rackhand-hub web::tests::forms::add_user_shows_every_problem_and_the_new_key_has_a_qr_code
FAIL [   8.253s] ( 8/12) rackhand-hub web::tests::forms::notifiers_show_every_problem_on_the_form_that_was_sent
FAIL [   8.253s] ( 9/12) rackhand-hub web::tests::forms::add_appliance_shows_every_problem_on_the_form_of_its_driver
FAIL [   8.253s] (10/12) rackhand-hub web::tests::forms::a_refused_decision_is_explained_on_the_approvals_page
FAIL [   8.253s] (11/12) rackhand-hub web::tests::forms::a_draft_that_cannot_be_applied_is_explained_in_the_library
FAIL [   8.690s] (12/12) rackhand-hub web::tests::forms::the_last_admin_is_explained_on_the_settings_page
Summary [   8.691s] 12 tests run: 0 passed, 12 failed, 318 skipped
```

After this run one expectation was corrected: a draft that is not pending has always been answered with 400, and the
new test first said 404. Its other assertion (the reason on the Library page) is the one that failed.

## Before: attempts without a setup code
```
FAIL [   0.145s] (1/1) rackhand-hub web::tests::first_run::attempts_without_a_setup_code_are_limited_too
Summary [   0.146s] 1 test run: 0 passed, 1 failed, 334 skipped
```

## The four tests written after their change, each with that change broken on purpose
```
FAIL web::tests::forms::a_failed_test_message_stays_on_the_notifiers_page   (its failure on a bare page)
FAIL web::tests::forms::held_secrets_expire_and_work_once                    (held secrets never expire)
FAIL web::tests::forms::wrong_codes_keep_the_step_and_the_last_one_says_why_it_ends (nothing said)
FAIL web::tests::forms::the_rules_shown_are_the_rules_kept                   (a site name of up to 40)
```

## After

| Check | Result |
| --- | --- |
| `cargo xtask ci fast` (fmt, clippy with warnings denied, dependency rules, `cargo deny`, tests) | 550 passed, 1 skipped (`xtask` test marked `ignore` before this branch: it builds the workspace twice) |
| `cargo xtask arch-check` | no violations |
| The built hub walked over HTTPS with curl, trusting its own certificate: every problem at once, a wrong then a right setup code, the password kept and not sent back, a wrong then a right authenticator code, the recovery code once | as designed |
| The same in a browser, with the part 1 build, 2026-11-22: checks while typing, the timezone preselected, four problems at once, setup code accepted and password kept, QR code, copy button, a wrong code with the same key, the right code, the recovery code; desktop and phone width | as designed; screenshots with the owner |
| Integration tier, lab deploy, live tier | compiled only |

## Part 2, before
```
FAIL [   0.013s] ( 1/16) rackhand-hub web::tests::shell::every_color_pair_can_be_read_in_both_themes
FAIL [   0.093s] ( 2/16) rackhand-hub web::tests::shell::what_an_approval_runs_is_never_broken_inside_a_word
FAIL [   0.096s] ( 3/16) rackhand-hub web::tests::shell::shortcuts_come_from_one_table
FAIL [   0.097s] ( 4/16) rackhand-hub web::tests::shell::stepping_up_returns_to_what_asked_for_it
FAIL [   0.098s] ( 5/16) rackhand-hub web::tests::shell::the_shell_offers_only_what_the_role_can_open
FAIL [   0.098s] ( 6/16) rackhand-hub web::tests::shell::every_removal_asks_with_the_safe_choice_first
FAIL [   0.102s] ( 7/16) rackhand-hub web::tests::shell::fields_that_depend_on_a_choice_say_so
FAIL [   0.103s] ( 8/16) rackhand-hub web::tests::shell::a_window_is_picked_from_day_time_and_length
FAIL [   0.103s] ( 9/16) rackhand-hub web::tests::shell::the_theme_is_chosen_per_browser
FAIL [   0.104s] (10/16) rackhand-hub web::tests::shell::dialogs_have_addresses_and_come_drawn_open
FAIL [   0.104s] (11/16) rackhand-hub web::tests::shell::errors_are_shown_in_the_shell
FAIL [   0.104s] (12/16) rackhand-hub web::tests::shell::every_page_has_the_shell
FAIL [   0.104s] (13/16) rackhand-hub web::tests::shell::the_version_is_shown_and_an_update_can_be_noticed
FAIL [   0.108s] (14/16) rackhand-hub web::tests::shell::lists_are_searched_by_the_hub_too
FAIL [   0.130s] (15/16) rackhand-hub web::tests::shell::lists_inform_and_dialogs_change
FAIL [   0.133s] (16/16) rackhand-hub web::tests::shell::new_passwords_are_typed_twice
Summary [   0.139s] 16 tests run: 0 passed, 16 failed, 335 skipped
```
