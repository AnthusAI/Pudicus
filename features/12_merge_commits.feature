Feature: Merge commits
  As a developer who merges branches every day
  I want LeftBlock to inspect what a merge itself introduces
  So that content I merely inherit from a parent does not block me, while anything new I add in the merge is still caught

  An ordinary commit is inspected for the lines it adds. A merge commit would
  naively "add" everything the other branch brought, including material that
  was already in the repository, so LeftBlock leaves out files that arrive
  unchanged from a parent, at the same path and with the same mode. It does
  this conservatively: a file the merge modifies, renames, creates or
  re-moded is inspected in full, so new context or a new combination of
  inherited lines cannot slip through, and whenever the merge cannot be
  understood the whole staged tree is inspected instead. Inheriting content
  is not a statement that it is safe, only that this commit did not add it.

  Background:
    Given a repository with LeftBlock installed as a local check-only gate
    And the history is on a branch called "trunk"

  @gitleaks
  Scenario: A plain commit with a flagged line is still blocked
    Given a staged file "notes.txt" containing a synthetic flagged session line
    When I run "leftblock check"
    Then the exit code is 1
    And stderr contains "leftblock-session-uuid"

  # --- What a merge inherits ------------------------------------------------

  @gitleaks
  Scenario: Files that arrive unchanged from the other parent are not inspected again
    Given the file "base.txt" is committed
    And a branch "feature" is created from the current one and checked out
    And the current branch gains a commit adding "feature.txt" containing a synthetic harmless code
    And the branch "trunk" is checked out
    And the current branch gains a commit adding "inherited.txt" containing a synthetic flagged session line
    And the branch "feature" is checked out
    And a merge of "trunk" is in progress, not yet committed
    When I commit the staged files
    Then the commit succeeds

  @gitleaks
  Scenario: A merge resolution that adds a new flagged line is blocked
    Given the current branch gains a commit adding "shared.txt" containing:
      """
      one
      """
    And a branch "feature" is created from the current one and checked out
    And the current branch gains a commit replacing "shared.txt" with:
      """
      one
      feature
      """
    And the branch "trunk" is checked out
    And the current branch gains a commit adding "inherited.txt" containing a synthetic flagged session line
    And the current branch gains a commit replacing "shared.txt" with:
      """
      one
      trunk
      """
    And the branch "feature" is checked out
    And a merge of "trunk" is in progress, not yet committed
    And a staged file "shared.txt" containing a synthetic another flagged session line
    When I commit the staged files
    Then the commit is blocked
    And HEAD has not moved
    And stderr contains "shared.txt"
    And stderr contains "leftblock-session-uuid"

  @gitleaks
  Scenario: A brand-new file added by the merge is inspected in full
    Given the file "base.txt" is committed
    And a branch "feature" is created from the current one and checked out
    And the current branch gains a commit adding "feature.txt" containing a synthetic harmless code
    And the branch "trunk" is checked out
    And the current branch gains a commit adding "trunk.txt" containing a synthetic harmless code
    And the branch "feature" is checked out
    And a merge of "trunk" is in progress, not yet committed
    And a staged file "extra.txt" containing a synthetic flagged session line
    When I run "leftblock check"
    Then the exit code is 1
    And stderr contains "extra.txt"

  @gitleaks
  Scenario: A file renamed on one branch and edited on the other merges without trouble
    Given the current branch gains a commit adding "old.txt" containing:
      """
      a
      b
      c
      d
      e
      f
      """
    And the current branch gains a commit adding "flagged.txt" containing a synthetic flagged session line
    And a branch "feature" is created from the current one and checked out
    And the current branch gains a commit renaming "flagged.txt" to "renamed.txt"
    And the branch "trunk" is checked out
    And the current branch gains a commit replacing "old.txt" with:
      """
      a
      b
      c
      d
      e
      f
      g
      """
    And the branch "feature" is checked out
    And a merge of "trunk" is in progress, not yet committed
    When I run "leftblock check"
    Then the exit code is 0

  @gitleaks
  Scenario: Renaming a board file into another context does not carry its exemption along
    Given a staged file "project/events/event.json" containing a synthetic actor id
    And the file "project/events/event.json" is committed
    And a branch "feature" is created from the current one and checked out
    And the current branch gains a commit adding "feature.txt" containing a synthetic harmless code
    And the branch "trunk" is checked out
    And the current branch gains a commit adding "trunk.txt" containing a synthetic harmless code
    And a merge of "feature" is in progress, not yet committed
    And the staged file "project/events/event.json" is renamed to "telemetry.json"
    When I commit the staged files
    Then the commit is blocked
    And HEAD has not moved
    And stderr contains "leftblock-session-uuid"

  @gitleaks
  Scenario: Lines that each exist in a parent are inspected again when the merge combines them
    Given the local policy also flags the three-line block "SYNTHETIC_BEGIN", "fixture_payload", "SYNTHETIC_END"
    And the current branch gains a commit adding "assembled.txt" containing:
      """
      baseline
      """
    And a branch "feature" is created from the current one and checked out
    And the current branch gains a commit replacing "assembled.txt" with:
      """
      SYNTHETIC_BEGIN
      break
      fixture_payload
      break
      SYNTHETIC_END
      """
    And the branch "trunk" is checked out
    And the current branch gains a commit adding "trunk.txt" containing a synthetic harmless code
    And a merge of "feature" is in progress, not yet committed
    And a staged file "assembled.txt" containing:
      """
      SYNTHETIC_BEGIN
      fixture_payload
      SYNTHETIC_END
      """
    When I run "leftblock check"
    Then the exit code is 1
    And stderr contains "synthetic-multiline"

  @gitleaks
  Scenario: A modified imported file keeps its inherited findings
    Given a branch "feature" is created from the current one and checked out
    And the current branch gains a commit adding "imported.txt" containing a synthetic flagged session line
    And the branch "trunk" is checked out
    And the current branch gains a commit adding "trunk.txt" containing a synthetic harmless code
    And a merge of "feature" is in progress, not yet committed
    And "imported.txt" is changed by one more harmless line and staged
    When I run "leftblock check"
    Then the exit code is 1
    And stderr contains "imported.txt"

  @gitleaks
  Scenario: An imported file whose mode changes is inspected in full
    Given a branch "feature" is created from the current one and checked out
    And the current branch gains a commit adding "imported.txt" containing a synthetic flagged session line
    And the branch "trunk" is checked out
    And the current branch gains a commit adding "trunk.txt" containing a synthetic harmless code
    And a merge of "feature" is in progress, not yet committed
    And "imported.txt" is staged as executable
    When I run "leftblock check"
    Then the exit code is 1
    And stderr contains "imported.txt"

  @gitleaks
  Scenario: An imported symbolic link is still inspected
    Given a branch "feature" is created from the current one and checked out
    And the current branch gains a commit adding a symlink "shortcut" whose target is a synthetic flagged session line
    And the branch "trunk" is checked out
    And the current branch gains a commit adding "trunk.txt" containing a synthetic harmless code
    And a merge of "feature" is in progress, not yet committed
    When I run "leftblock check"
    Then the exit code is 1
    And stderr contains "shortcut"

  @gitleaks
  Scenario: Binary files and submodule pointers staged in a merge do not hide a flagged file
    Given a branch "feature" is created from the current one and checked out
    And the current branch gains a commit adding "feature.txt" containing a synthetic harmless code
    And the branch "trunk" is checked out
    And the current branch gains a commit adding "trunk.txt" containing a synthetic harmless code
    And a merge of "feature" is in progress, not yet committed
    And a binary file "payload.bin" and a submodule pointer "vendored" are staged
    And a staged file "resolution.txt" containing a synthetic flagged session line
    When I run "leftblock check"
    Then the exit code is 1
    And stderr contains "resolution.txt"

  # --- When the merge cannot be understood ---------------------------------

  @gitleaks
  Scenario Outline: A merge whose parents cannot be read falls back to inspecting everything
    Given a branch "feature" is created from the current one and checked out
    And the current branch gains a commit adding "imported.txt" containing a synthetic flagged session line
    And the branch "trunk" is checked out
    And the current branch gains a commit adding "trunk.txt" containing a synthetic harmless code
    And a merge of "feature" is in progress, not yet committed
    And the merge records <state> as its parent
    When I run "leftblock check"
    Then the exit code is 1
    And stderr contains "imported.txt"

    Examples: damaged merge state
      | state                                    |
      | text that is not a commit id             |
      | the id of a commit that does not exist   |
      | the id of a tree                         |
      | nothing                                  |
      | no parent at all                         |

  # --- Several parents -----------------------------------------------------

  @gitleaks
  Scenario: An octopus merge ignores what its parents bring and catches what the resolution adds
    Given the file "base.txt" is committed
    And a branch "one" is created from the current one and checked out
    And the current branch gains a commit adding "one.txt" containing a synthetic flagged session line
    And the branch "trunk" is checked out
    And a branch "two" is created from the current one and checked out
    And the current branch gains a commit adding "two.txt" containing a synthetic another flagged session line
    And the branch "trunk" is checked out
    And the current branch gains a commit adding "trunk.txt" containing a synthetic harmless code
    And an octopus merge of "one" and "two" is in progress, not yet committed
    When I run "leftblock check"
    Then the exit code is 0
    Given a staged file "resolution.txt" containing a synthetic flagged session line
    When I run "leftblock check"
    Then the exit code is 1
    And stderr contains "resolution.txt"

  # --- Unstable inspection ---------------------------------------------------

  Scenario: A merge parent that changes while the checkers run blocks the check
    Given a branch "feature" is created from the current one and checked out
    And the current branch gains a commit adding "feature.txt" containing a synthetic harmless code
    And the branch "trunk" is checked out
    And the current branch gains a commit adding "trunk.txt" containing a synthetic harmless code
    And a merge of "feature" is in progress, not yet committed
    And a checker script "forget_merge.py" containing:
      """
      import os
      os.remove(".git/MERGE_HEAD")
      """
    And the local policy is replaced by:
      """
      checkers:
        - name: forgetful-scanner
          type: command
          command: $PYTHON $CHECKERS/forget_merge.py
      """
    When I run "leftblock check"
    Then the exit code is 2
    And stderr contains "merge-scope"

  Scenario: A checker that alters the inspected files during a merge cannot report a clean result
    Given a branch "feature" is created from the current one and checked out
    And the current branch gains a commit adding "feature.txt" containing a synthetic harmless code
    And the branch "trunk" is checked out
    And the current branch gains a commit adding "trunk.txt" containing a synthetic harmless code
    And a merge of "feature" is in progress, not yet committed
    And a staged file "resolution.txt" containing a synthetic harmless code
    And the local policy is replaced by:
      """
      checkers:
        - name: index-editing-scanner
          type: command
          command: git update-index --force-remove resolution.txt
      """
    When I run "leftblock check"
    Then the exit code is 2
    And stderr contains "merge-scope"
    And "resolution.txt" is still staged

  @gitleaks
  Scenario: A merge with unresolved conflicts is reported plainly, not with a stack trace
    Given the current branch gains a commit adding "shared.txt" containing:
      """
      one
      """
    And a branch "feature" is created from the current one and checked out
    And the current branch gains a commit adding "imported.txt" containing a synthetic flagged session line
    And the current branch gains a commit replacing "shared.txt" with:
      """
      one
      feature
      """
    And the branch "trunk" is checked out
    And the current branch gains a commit replacing "shared.txt" with:
      """
      one
      trunk
      """
    And a merge of "feature" is in progress, not yet committed
    When I run "leftblock check"
    Then the exit code is 2
    And stderr contains "unresolved conflicts"
    And stderr contains "Resolve the conflicts"
    And stderr does not contain "Traceback"
