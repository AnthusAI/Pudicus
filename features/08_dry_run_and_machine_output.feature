Feature: Dry run and machine output
  As a developer, or a tool that drives Git for one
  I want to preview the next commit without making it, and read the verdict as data
  So that I can fix problems before committing and wire LeftBlock into scripts and wrappers

  "leftblock check" inspects the staged changes with the same policy the commit
  hook uses and changes nothing: no commit, no staging, no files. Without
  "--config" it uses the policy of the local install when there is one, and only
  otherwise the ".leftblock.yml" at the repository root. Exit codes are 0 for
  passed, 1 for findings and 2 when a checker or the configuration could not
  complete. "--format json" adds one JSON report on stdout and leaves the
  human-readable output on stderr unchanged; neither ever contains a matched value.

  @gitleaks
  Scenario: A dry run reports findings and changes nothing
    Given a repository with LeftBlock installed as a local check-only gate
    And a staged file "page.tsx" containing a synthetic personal email
    And I remember the staged tree
    When I run "leftblock check"
    Then the exit code is 1
    And stderr contains "leftblock-personal-email"
    And the output does not reveal the synthetic value
    And HEAD has not moved
    And the staged tree is exactly as remembered

  @gitleaks
  Scenario: A dry run ends by printing the command to run it again
    Given a repository with LeftBlock installed as a local check-only gate
    And a staged file "page.tsx" containing a synthetic personal email
    When I run "leftblock check"
    Then stderr contains "Re-run this check:"
    And stderr does not contain "check --config"

  @gitleaks
  Scenario: A dry run of clean changes passes
    Given a repository with LeftBlock installed as a local check-only gate
    And a staged file "app.py" containing a synthetic harmless code
    When I run "leftblock check"
    Then the exit code is 0
    And stderr contains "All configured checks passed"
    And HEAD has not moved

  @gitleaks
  Scenario: A dry run inspects only what is staged
    Given a repository with LeftBlock installed as a local check-only gate
    And the file "notes.txt" is committed
    And an unstaged change to "notes.txt" containing a synthetic personal email
    And a staged file "app.py" containing a synthetic harmless code
    When I run "leftblock check"
    Then the exit code is 0

  @gitleaks
  Scenario: The local install policy wins over a policy at the repository root
    Given a repository with LeftBlock installed as a local check-only gate
    And a root policy whose only scanner accepts everything
    And a staged file "page.tsx" containing a synthetic personal email
    When I run "leftblock check"
    Then the exit code is 1
    And stderr contains "leftblock-personal-email"

  Scenario: Without a local install the dry run uses the policy at the repository root
    Given a repository without LeftBlock
    And a root policy whose only scanner always reports a finding
    And a staged file "app.py" containing a synthetic harmless code
    When I run "leftblock check"
    Then the exit code is 1
    And stderr contains "Inspection blocked"

  Scenario: Without a local install a root policy that accepts everything passes
    Given a repository without LeftBlock
    And a root policy whose only scanner accepts everything
    And a staged file "app.py" containing a synthetic harmless code
    When I run "leftblock check"
    Then the exit code is 0

  @gitleaks
  Scenario: A passing JSON report is empty and exits 0
    Given a repository with LeftBlock installed as a local check-only gate
    And a staged file "app.py" containing a synthetic harmless code
    When I run "leftblock check --format json"
    Then the exit code is 0
    And stdout is valid JSON with "result" equal to "passed"
    And the JSON report has a version equal to the installed version
    And stdout is valid JSON with "findings" equal to "[]"
    And stdout is valid JSON with "overrides_applied" equal to "[]"
    And stdout is valid JSON with "errors" equal to "[]"
    And stdout is valid JSON with "override_command" equal to "null"
    And stderr contains "All configured checks passed"

  @gitleaks
  Scenario: A blocked JSON report lists each finding and exits 1
    Given a repository with LeftBlock installed as a local check-only gate
    And a staged file "page.tsx" containing a synthetic personal email
    When I run "leftblock check --format json"
    Then the exit code is 1
    And stdout is valid JSON with "result" equal to "blocked"
    And stdout is valid JSON with "findings.0.file" equal to "page.tsx"
    And stdout is valid JSON with "findings.0.line" equal to "1"
    And stdout is valid JSON with "findings.0.rule" equal to "leftblock-personal-email"
    And stdout is valid JSON with "findings.0.description" equal to "Personal email address"
    And the JSON finding has a 16-character hexadecimal id
    And stdout is valid JSON with "errors" equal to "[]"

  @gitleaks
  Scenario: The JSON report carries the override command and never the value
    Given a repository with LeftBlock installed as a local check-only gate
    And a staged file "page.tsx" containing a synthetic personal email
    When I run "leftblock check --format json"
    Then the JSON field "override_command" contains "allow"
    And the JSON field "override_command" contains "--reason"
    And the override command in the report names the finding id
    And the output does not reveal the synthetic value
    And stderr contains "Inspection blocked"

  @gitleaks
  Scenario: The text format keeps stdout empty
    Given a repository with LeftBlock installed as a local check-only gate
    And a staged file "page.tsx" containing a synthetic personal email
    When I run "leftblock check"
    Then the exit code is 1
    And the dry run prints nothing on stdout

  @gitleaks
  Scenario: The JSON report lists the overrides that were applied
    Given a repository with LeftBlock installed as a local check-only gate
    And a staged file "page.tsx" containing a synthetic personal email
    And an override is recorded for the staged finding because "Public role address for the site"
    When I run "leftblock check --format json"
    Then the exit code is 0
    And stdout is valid JSON with "result" equal to "passed"
    And stdout is valid JSON with "overrides_applied.0.file" equal to "page.tsx"
    And stdout is valid JSON with "overrides_applied.0.rule" equal to "leftblock-personal-email"
    And stdout is valid JSON with "overrides_applied.0.reason" equal to "Public role address for the site"
    And the JSON override applied has the id of the recorded override

  @gitleaks
  Scenario Outline: An invalid allow file is an error in both formats
    Given a repository with LeftBlock installed as a local check-only gate
    And a staged file "app.py" containing a synthetic harmless code
    And a staged file ".leftblock-allow.yml" containing:
      """
      version: 2
      allow: []
      """
    When I run "leftblock check --format <format>"
    Then the exit code is 2
    And stderr contains "Invalid .leftblock-allow.yml"

    Examples:
      | format |
      | text   |
      | json   |

  @gitleaks
  Scenario: An invalid allow file is described in the JSON report
    Given a repository with LeftBlock installed as a local check-only gate
    And a staged file "app.py" containing a synthetic harmless code
    And a staged file ".leftblock-allow.yml" containing:
      """
      version: 2
      allow: []
      """
    When I run "leftblock check --format json"
    Then stdout is valid JSON with "result" equal to "error"
    And stdout is valid JSON with "errors.0.checker" equal to "leftblock-allow"
    And the JSON field "errors.0.message" contains "Invalid .leftblock-allow.yml"

  Scenario Outline: A policy that cannot be read is an error in both formats
    Given a repository without LeftBlock
    And a staged file "app.py" containing a synthetic harmless code
    When I run "leftblock check --config missing-policy.json --format <format>"
    Then the exit code is 2

    Examples:
      | format |
      | text   |
      | json   |

  Scenario: A policy that cannot be read is described in the JSON report
    Given a repository without LeftBlock
    And a staged file "app.py" containing a synthetic harmless code
    When I run "leftblock check --config missing-policy.json --format json"
    Then stdout is valid JSON with "result" equal to "error"
    And stdout is valid JSON with "errors.0.checker" equal to "configuration"

  @gitleaks
  Scenario Outline: Exit codes are the same in both formats
    Given a repository with LeftBlock installed as a local check-only gate
    And a staged file "page.tsx" containing a synthetic <content>
    When I run "leftblock check --format <format>"
    Then the exit code is <code>

    Examples:
      | content        | format | code |
      | harmless code  | text   | 0    |
      | harmless code  | json   | 0    |
      | personal email | text   | 1    |
      | personal email | json   | 1    |

  Scenario: The installed version is printed on request
    When I run "leftblock --version"
    Then the exit code is 0
    And the version line names the installed LeftBlock
