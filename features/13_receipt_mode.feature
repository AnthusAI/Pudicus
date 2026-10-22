@gitleaks
Feature: Receipt mode
  As a development team
  We want an optional mode that records the inspection result inside each commit
  So that a later check can prove which commits were inspected, and what the verdict was

  Receipt mode installs a commit-msg hook. A commit that passes is stamped with
  trailers carrying a signature (HMAC) over its tree, made with a secret kept
  outside the repository. Findings block the commit unless a human at a terminal
  approves them with the shared passphrase, or a reviewer has recorded the
  finding as an override that is committed with the change. Errors are never
  approvable. "leftblock verify" later checks the signatures, which cover the
  validator name, the tree, the result and the time.

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

  # --- Reading the receipt ---------------------------------------------------

  Scenario: The receipt names the exact tree that was committed
    Given a repository with LeftBlock installed in receipt mode
    And a staged file "app.py" containing a synthetic harmless code
    When I commit the staged files
    Then the receipt of the latest commit names the tree it actually contains

  Scenario: A merge commit's receipt signs the real tree, not the reduced view the checkers saw
    Given a repository with LeftBlock installed in receipt mode
    And the temporary directory is a private folder named "private scratch"
    And the history is on a branch called "trunk"
    And the file "base.txt" is committed
    And a branch "feature" is created from the current one and checked out
    And the current branch gains a commit adding "imported.txt" containing a synthetic flagged session line
    And the branch "trunk" is checked out
    And the current branch gains a commit adding "trunk.txt" containing a synthetic harmless code
    And a merge of "feature" is in progress, not yet committed
    When I commit the staged files
    Then the commit succeeds
    And the latest commit message contains "Inspected-by: leftblock-v1"
    And the receipt of the latest commit names the tree it actually contains
    And nothing is left in the private temporary folder

  # --- Findings and people ---------------------------------------------------

  Scenario: A person at a terminal can approve findings with the shared passphrase
    Given a repository with LeftBlock installed in receipt mode
    And a staged file "client.py" containing a synthetic OpenAI key
    When On an interactive terminal I run "leftblock hook $MESSAGE_FILE" and enter the shared passphrase
    Then the exit code is 0
    And stderr contains "Override approved"
    And the commit message file contains "Inspection-result: override:1-checkers"
    And the commit message file contains "Inspection-sig: hmac-sha256:"
    And the output does not reveal the synthetic value

  Scenario: A wrong passphrase leaves the commit blocked and unsigned
    Given a repository with LeftBlock installed in receipt mode
    And a staged file "client.py" containing a synthetic OpenAI key
    When On an interactive terminal I run "leftblock hook $MESSAGE_FILE" and enter a wrong passphrase
    Then the exit code is 1
    And stderr contains "Incorrect passphrase"
    And the commit message file does not contain "Inspection-sig"

  Scenario: Reviewed overrides need no passphrase and are recorded as allowed, not clean
    Given a repository with LeftBlock installed in receipt mode
    And a staged file "contacts.txt" containing a synthetic personal email
    And the staged findings are recorded as reviewed overrides
    When I commit the staged files
    Then the commit succeeds
    And the latest commit message contains "Inspection-result: allowed:1"
    And the latest commit message does not contain "Inspection-result: clean"
    And stderr contains "Override applied"

  Scenario: A commit with no overrides is recorded as clean
    Given a repository with LeftBlock installed in receipt mode
    And a staged file "app.py" containing a synthetic harmless code
    When I commit the staged files
    Then the commit succeeds
    And the latest commit message contains "Inspection-result: clean"
    And the latest commit message does not contain "allowed:"

  # --- Verifying -------------------------------------------------------------

  Scenario: Verification passes for every signed commit in a range
    Given a repository with LeftBlock installed in receipt mode
    And a staged file "one.py" containing a synthetic harmless code
    And the staged work is committed through the hook
    And a staged file "two.py" containing a synthetic harmless code
    And the staged work is committed through the hook
    When I run "leftblock verify HEAD~2..HEAD"
    Then the exit code is 0
    And stdout contains "All 2 commit(s) verified."

  Scenario: Verification fails for an unsigned commit and says how many
    Given a repository with LeftBlock installed in receipt mode
    And 2 unsigned commits
    When I run "leftblock verify HEAD~1..HEAD"
    Then the exit code is 1
    And stderr contains "No valid signature found"
    And stderr contains "Verification failed: 1/1 commit(s) invalid."

  Scenario: Verification cannot run without the shared secret
    Given a repository with LeftBlock installed in receipt mode
    And a commit made without the hook
    And the signing secret has been removed
    When I run "leftblock verify HEAD"
    Then the exit code is 1
    And stderr contains "Shared secret not found"

  Scenario: A receipt for a different secret does not verify
    Given a repository with LeftBlock installed in receipt mode
    And a commit signed by the validator "leftblock-v1"
    And the signing secret is replaced by a different one
    When I run "leftblock verify HEAD"
    Then the exit code is 1
    And stderr contains "No valid signature found"

  Scenario Outline: Receipts keep verifying under the validator name they were signed with
    Given a repository with LeftBlock installed in receipt mode
    And a commit signed by the validator "<validator>"
    When I run "leftblock verify HEAD"
    Then the exit code is 0
    And stdout contains "verified"

    Examples: a current and a historical validator name
      | validator              |
      | leftblock-v1           |
      | historical-inspector-v0 |

  Scenario: Renaming the validator stored in a receipt invalidates it
    Given a repository with LeftBlock installed in receipt mode
    And a commit signed by the validator "historical-inspector-v0"
    When the validator named in the latest receipt is changed to "leftblock-v1"
    And I run "leftblock verify HEAD"
    Then the exit code is 1
    And stderr contains "No valid signature found"
