# FortiSafe desktop accessibility review

Checklist version: 1.0 (2026-09-02)  
Target: WCAG 2.1 AA at 1024×768, 1440×900, and 1920×1080. Mobile is out of scope.

Automated axe checks are a regression gate, not a conformance claim. Review every
critical workflow below in English and German, with full, empty, loading, warning,
error, long-FQDN, and long-error fixtures where applicable.

## Keyboard and focus

- [ ] Tab order follows visual/task order without traps or unreachable controls.
- [ ] A visible focus indicator is present on every interactive element.
- [ ] Skip navigation reaches the main landmark.
- [ ] Disclosures work with Enter and Space and expose the correct expanded state.
- [ ] Dialogs receive focus, contain Tab/Shift+Tab, close with Escape, and return focus.
- [ ] Tabs use arrow-key navigation and preserve an intelligible reading order.
- [ ] Destructive actions require an explicit, keyboard-operable confirmation.

## Structure and names

- [ ] Page language, title, landmarks, one `h1`, and heading hierarchy are correct.
- [ ] Every input has a persistent visible label and associated help/error text.
- [ ] Tables have an accessible name, headers, and meaningful empty state.
- [ ] Icon-only actions have accessible names; decorative icons are hidden.
- [ ] Status is expressed with text or icon plus text, never color alone.

## Visual access

- [ ] Normal text contrast is at least 4.5:1; large text and UI boundaries are 3:1.
- [ ] Content remains usable at 200% browser zoom without document-level overflow.
- [ ] Reduced-motion mode removes nonessential animation and preserves feedback.
- [ ] Focus, hover, selected, disabled, warning, and error states remain distinguishable.

## Dynamic content

- [ ] Loading, success, warning, validation, and failure updates are announced once.
- [ ] Focus remains stable after polling and partial page updates.
- [ ] Progress communicates an accessible name, value, and completion state.
- [ ] Time toggles update visible timestamps without losing machine-readable RFC3339 values.

## Critical workflows

- [ ] Login, logout, password change, and authentication failure.
- [ ] Firewall add/edit/delete, backup/test, host-key review, and backup download.
- [ ] Search, audit, licenses, IPAM, topology, sharing, and activity/error review.
- [ ] ADM VPN Config add/edit/import/export and secret replacement.
- [ ] Policy Generator edit/generate/reset and unsaved-work warning.
- [ ] Policy Split analyze/progress/ambiguity/results/export.
- [ ] Config Converter recipe selection/port picker/preview/export.
- [ ] ConfTail filters/poll health/session timeline/Hookwise delivery/export.

Record reviewer, date, browser/OS, viewport, locale, scenario, failures, and linked
issue for every completed pass. Any waiver must name the exact axe rule or manual
criterion, affected route/state, reason, owner, and removal task.
