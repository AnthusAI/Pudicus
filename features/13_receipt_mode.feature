@gitleaks
Feature: Receipt mode
  As a development team
  We want an optional mode that records the inspection result inside each commit
  So that a later check can prove which commits were inspected, and what the verdict was

  Receipt mode installs a commit-msg hook. A commit that passes is stamped with
  trailers carrying a signature (HMAC) over its tree, made with a secret kept
  outside the repository. Findings block the commit unless a human at a terminal
  approves them. "leftblock verify" later checks the signatures.

  Scenario: A clean commit receives a signed receipt
    Given a repository with LeftBlock installed in receipt mode
    And a staged file "app.py" containing a synthetic harmless code
    When I commit the staged files
    Then the commit succeeds
    And the latest commit message contains "Inspected-by: leftblock-v1"
    And the latest commit message contains "Inspection-result: clean"
    And the latest commit message contains "Inspection-sig: hmac-sha256:"

  Scenario: A committed receipt verifies
    Given a repository with LeftBlock installed in receipt mode
    And a staged file "app.py" containing a synthetic harmless code
    When I commit the staged files
    And I run "leftblock verify HEAD"
    Then the exit code is 0
    And stdout contains "verified"

  Scenario: A commit with sensitive data is blocked when no human can approve it
    Given a repository with LeftBlock installed in receipt mode
    And a staged file "client.py" containing a synthetic OpenAI key
    When I commit the staged files
    Then the commit is blocked
    And HEAD has not moved
    And stderr contains "no interactive terminal"

  Scenario: A commit made without the hook has no receipt to verify
    Given a repository with LeftBlock installed in receipt mode
    And a commit made without the hook
    When I run "leftblock verify HEAD"
    Then the exit code is 1
    And stderr contains "No valid signature"
