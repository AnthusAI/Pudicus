Feature: Silent bypasses
  As a reviewer who relies on the commit gate
  I want the scanner's own ways of skipping content to leave a visible trace
  So that nobody can wave a finding through without a recorded reason

  The scanner underneath LeftBlock lets a line opt out with an inline allow
  comment, and lets a ".gitleaksignore" file list findings to skip, both with no
  reason attached. LeftBlock reports a staged addition of either as a finding of
  its own, so it blocks by default and can be cleared only through a recorded
  override like any other finding. Only added lines count, and removing a
  suppression is the fix, never a finding. The one thing LeftBlock cannot stop
  is a root ".gitleaksignore" that was already there; it announces it on every check.

  Rule "leftblock-gitleaks-allow-marker" is the inline comment and
  "leftblock-gitleaksignore-change" is the ignore file.

  # --- The inline allow comment ---------------------------------------

  @gitleaks
  Scenario: A line with the inline allow comment is a finding at its line number
    Given a repository with LeftBlock installed as a local check-only gate
    And a staged notes file "notes.md" of 3 lines with the inline allow marker on line 3
    When I run "leftblock check --format json"
    Then the exit code is 1
    And stdout is valid JSON with "findings.0.file" equal to "notes.md"
    And stdout is valid JSON with "findings.0.line" equal to "3"
    And stdout is valid JSON with "findings.0.rule" equal to "leftblock-gitleaks-allow-marker"
    And the JSON finding has a 16-character hexadecimal id

  @gitleaks
  Scenario: The finding is shown at its line in the readable output too
    Given a repository with LeftBlock installed as a local check-only gate
    And a staged notes file "notes.md" of 3 lines with the inline allow marker on line 3
    When I run "leftblock check"
    Then stderr contains "notes.md:3: leftblock-gitleaks-allow-marker"

  @gitleaks
  Scenario: The commit is blocked until the marker is removed or overridden
    Given a repository with LeftBlock installed as a local check-only gate
    And a staged notes file "notes.md" of 3 lines with the inline allow marker on line 3
    When I commit the staged files
    Then the commit is blocked
    And HEAD has not moved

  @gitleaks
  Scenario: A recorded override clears the marker finding
    Given a repository with LeftBlock installed as a local check-only gate
    And a staged notes file "notes.md" of 3 lines with the inline allow marker on line 3
    When I note the ids the bypass check reports
    And I record overrides for the reported bypasses because "Reviewed: documentation example"
    And I run "leftblock check --format json"
    Then the exit code is 0
    And stdout is valid JSON with "overrides_applied.0.rule" equal to "leftblock-gitleaks-allow-marker"
    And stderr contains "Reviewed: documentation example"

  @gitleaks
  Scenario: An overridden marker line commits
    Given a repository with LeftBlock installed as a local check-only gate
    And a staged notes file "notes.md" of 3 lines with the inline allow marker on line 3
    When I note the ids the bypass check reports
    And I record overrides for the reported bypasses because "Reviewed: documentation example"
    And I commit the staged files
    Then the commit succeeds

  @gitleaks
  Scenario: Changing an overridden marker line blocks it again
    Given a repository with LeftBlock installed as a local check-only gate
    And a staged notes file "notes.md" of 1 lines with the inline allow marker on line 1
    When I note the ids the bypass check reports
    And I record overrides for the reported bypasses because "Reviewed: documentation example"
    And I stage "notes.md" with its marker line edited
    And I run "leftblock check"
    Then the exit code is 1
    And stderr contains "notes.md:1: leftblock-gitleaks-allow-marker"

  @gitleaks
  Scenario: A marker line that was already committed is not inspected again
    Given a repository with LeftBlock installed as a local check-only gate
    And a committed notes file "notes.md" whose first line carries the inline allow marker
    And I stage "notes.md" with one more plain line
    When I run "leftblock check"
    Then the exit code is 0

  @gitleaks
  Scenario: Removing a marker is the fix and not a finding
    Given a repository with LeftBlock installed as a local check-only gate
    And a committed notes file "notes.md" whose first line carries the inline allow marker
    And I stage "notes.md" with the inline allow marker removed
    When I run "leftblock check"
    Then the exit code is 0

  @gitleaks
  Scenario: Only the newly added marker line is reported
    Given a repository with LeftBlock installed as a local check-only gate
    And a committed notes file "notes.md" whose first line carries the inline allow marker
    And I stage "notes.md" with one more line carrying the inline allow marker
    When I run "leftblock check"
    Then the exit code is 1
    And stderr contains "notes.md:3:"
    And stderr does not contain "notes.md:1:"

  @gitleaks
  Scenario: The marker does not hide a real finding on the same line
    Given a repository with LeftBlock installed as a local check-only gate
    And a staged notes file "notes.md" with a personal address and the inline allow marker on one line
    When I run "leftblock check"
    Then the exit code is 1
    And stderr contains "leftblock-gitleaks-allow-marker"
    And stderr contains "leftblock-personal-email"
    And the output does not reveal the synthetic value

  # --- Ignore files ---------------------------------------------------

  @gitleaks
  Scenario: Adding a root ignore file is a finding
    Given a repository with LeftBlock installed as a local check-only gate
    And a staged file ".gitleaksignore" containing:
      """
      old.txt:some-rule:1
      """
    When I run "leftblock check --format json"
    Then the exit code is 1
    And stdout is valid JSON with "findings.0.file" equal to ".gitleaksignore"
    And stdout is valid JSON with "findings.0.rule" equal to "leftblock-gitleaksignore-change"

  @gitleaks
  Scenario: An ignore file at any depth is a finding
    Given a repository with LeftBlock installed as a local check-only gate
    And a staged file "sub/dir/.gitleaksignore" containing:
      """
      old.txt:some-rule:2
      """
    When I run "leftblock check --format json"
    Then the exit code is 1
    And stdout is valid JSON with "findings.0.file" equal to "sub/dir/.gitleaksignore"
    And stdout is valid JSON with "findings.0.rule" equal to "leftblock-gitleaksignore-change"

  @gitleaks
  Scenario: Ignore files are cleared by recorded overrides, once per file
    Given a repository with LeftBlock installed as a local check-only gate
    And a staged file ".gitleaksignore" containing:
      """
      old.txt:some-rule:1
      """
    And a staged file "sub/dir/.gitleaksignore" containing:
      """
      old.txt:some-rule:2
      """
    When I note the ids the bypass check reports
    Then the reported bypasses are 2
    When I record overrides for the reported bypasses because "Reviewed: ignore file for a fixture"
    And I run "leftblock check"
    Then the exit code is 0
    And stderr contains "Override applied"

  @gitleaks
  Scenario: Overridden ignore files commit
    Given a repository with LeftBlock installed as a local check-only gate
    And a staged file ".gitleaksignore" containing:
      """
      old.txt:some-rule:1
      """
    When I note the ids the bypass check reports
    And I record overrides for the reported bypasses because "Reviewed: ignore file for a fixture"
    And I commit the staged files
    Then the commit succeeds

  @gitleaks
  Scenario: Editing a committed ignore file is a finding again
    Given a repository with LeftBlock installed as a local check-only gate
    And a staged file ".gitleaksignore" containing:
      """
      old.txt:some-rule:1
      """
    And the file ".gitleaksignore" is committed
    And I stage ".gitleaksignore" with one more plain line
    When I run "leftblock check"
    Then the exit code is 1
    And stderr contains "leftblock-gitleaksignore-change"

  @gitleaks
  Scenario: Removing an ignore file is the fix and not a finding
    Given a repository with LeftBlock installed as a local check-only gate
    And a staged file ".gitleaksignore" containing:
      """
      old.txt:some-rule:1
      """
    And the file ".gitleaksignore" is committed
    And I stage the removal of ".gitleaksignore"
    When I run "leftblock check"
    Then the exit code is 0

  # --- What LeftBlock cannot stop -----------------------------------------

  @gitleaks
  Scenario: A root ignore file is announced on every check
    Given a repository with LeftBlock installed as a local check-only gate
    And a staged file "notes.md" containing:
      """
      plain text
      """
    And the working tree has a root ignore file with no entries
    When I run "leftblock check"
    Then stderr contains "root .gitleaksignore"
    And stderr contains "prefer leftblock allow"

  @gitleaks
  Scenario: Without a root ignore file there is no announcement
    Given a repository with LeftBlock installed as a local check-only gate
    And a staged file "notes.md" containing:
      """
      plain text
      """
    When I run "leftblock check"
    Then stderr does not contain ".gitleaksignore"

  @gitleaks
  Scenario: Residual risk, a root ignore file that already existed still hides a finding
    Given a repository with LeftBlock installed as a local check-only gate
    And a committed root ignore file that skips the personal email finding on line 1 of "page.txt"
    And a staged file "page.txt" containing a synthetic personal email
    When I run "leftblock check"
    Then the exit code is 0
    And stderr contains "root .gitleaksignore"
