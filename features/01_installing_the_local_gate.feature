Feature: Installing the local gate
  As a developer who wants a pre-commit gate in one repository
  I want a single command that installs it without disturbing anything I already have
  So that I can adopt LeftBlock today and remove or upgrade it later without cleanup

  "leftblock install --local --check-only" adds a pre-commit hook, a policy
  and the shipped detection rules to the repository's Git directory, and
  nothing else: no tracked file, no signing secret, no change to hooks you
  already have. It can be run again safely. Whenever it meets something it
  does not own (another pre-commit hook, a hook manager, a file you edited,
  a symlink, a missing scanner) it stops with a message and leaves
  everything exactly as it was. The last section covers the optional receipt
  mode, whose installation follows the same rules.

  # --- What installation writes ------------------------------------------

  Scenario: Installing writes the gate under the Git directory only
    Given a repository without LeftBlock
    And the state of the repository is recorded
    When I install the local gate
    Then the exit code is 0
    And the local gate is stored in the common git directory only
    And the pre-commit hook is executable
    And the working tree is as it was recorded

  Scenario: Installing leaves the owner's files and hooks alone
    Given a repository without LeftBlock
    And the repository has an untracked owner file ".leftblock.yml"
    And the repository has its own "commit-msg" hook
    And the state of the repository is recorded
    When I install the local gate
    Then the exit code is 0
    And the working tree is as it was recorded
    And the owner's "commit-msg" hook is as the owner wrote it

  Scenario: The hook runs the check in isolation against the stored policy
    Given a repository with LeftBlock installed as a local check-only gate
    Then the hook runs LeftBlock in isolated mode against the stored policy
    And the policy, rules and ownership state are private to their owner
    And the recorded ownership matches the installed policy

  Scenario: The local gate needs no signing secret
    Given a repository without LeftBlock
    When I install the local gate
    Then the exit code is 0
    And no signing secret has been created

  Scenario Outline: Both flags are required
    Given a repository without LeftBlock
    When I run "leftblock install <flags>"
    Then the exit code is 1
    And stderr contains "--local and --check-only together"
    And no pre-commit hook is installed

    Examples:
      | flags        |
      | --local      |
      | --check-only |

  Scenario: The scanner option belongs to the local gate
    Given a repository without LeftBlock
    When I run "leftblock install --gitleaks some-scanner"
    Then the exit code is 1
    And stderr contains "--gitleaks is supported with --local --check-only"
    And no commit-msg hook or ownership state is installed

  Scenario: Installation needs a Git repository
    When I run "leftblock install --local --check-only"
    Then the exit code is 1
    And stderr contains "inside a Git repository"

  Scenario: Reinstalling changes nothing
    Given a repository with LeftBlock installed as a local check-only gate
    And the state of the repository is recorded
    When I install the local gate
    Then the exit code is 0
    And nothing in the repository has changed since it was recorded

  # --- Linked worktrees ----------------------------------------------------

  Scenario: Linked worktrees share the gate
    Given a repository without LeftBlock
    And a linked worktree "linked" of the repository
    And I work from the linked worktree "linked"
    When I install the local gate
    Then the exit code is 0
    And the pre-commit hook lives in the main repository's git directory
    And the linked worktree has no LeftBlock policy file

  @gitleaks
  Scenario: A commit made in a linked worktree is guarded
    Given a repository with LeftBlock installed as a local check-only gate
    And a linked worktree "linked" of the repository
    And I work from the linked worktree "linked"
    And a staged file "client.py" containing a synthetic OpenAI key
    When I commit the staged files
    Then the commit is blocked
    And HEAD has not moved

  # --- Policy selection ----------------------------------------------------

  Scenario Outline: An explicit policy that cannot be used fails closed
    Given a repository without LeftBlock
    And the repository has a checker policy ".leftblock.yml" that always passes
    When I run "leftblock check --config <config>"
    Then the exit code is 2
    And stderr does not contain "passed"

    Examples:
      | config         |
      | missing-policy |
      | ""             |

  Scenario: Without an explicit policy the root policy applies
    Given a repository without LeftBlock
    And the repository has a checker policy ".leftblock.yml" that always passes
    When I run "leftblock check"
    Then the exit code is 0

  # --- First commits ---------------------------------------------------------

  @gitleaks
  Scenario: The first clean commit passes
    Given a repository with LeftBlock installed as a local check-only gate
    And a staged file "fixture.txt" containing a synthetic harmless code
    When I commit the staged files
    Then the commit succeeds
    And no signing secret has been created

  @gitleaks
  Scenario: A sensitive commit is blocked before history changes
    Given a repository with LeftBlock installed as a local check-only gate
    And a staged file "fixture.txt" containing a synthetic harmless code
    And the file "fixture.txt" is committed
    And a staged file "fixture.txt" containing a synthetic OpenAI key
    When I commit the staged files
    Then the commit is blocked
    And HEAD has not moved
    And stderr contains "leftblock-openai-key"
    And the output does not reveal the synthetic value
    And no signing secret has been created

  # --- What installation refuses to touch ----------------------------------

  Scenario Outline: A pre-commit hook that is not LeftBlock's is never replaced
    Given a repository without LeftBlock
    And <foreign hook>
    And the state of the repository is recorded
    When I install the local gate
    Then the exit code is 1
    And stderr contains "unmanaged"
    And nothing in the repository has changed since it was recorded
    And the owner's "pre-commit" hook is as the owner wrote it
    And LeftBlock has created no policy directory

    Examples:
      | foreign hook                                                         |
      | the repository has its own "pre-commit" hook                         |
      | the repository has its own "pre-commit" hook that is not executable  |

  Scenario: A policy LeftBlock did not write is never replaced
    Given a repository without LeftBlock
    And an unmanaged local policy exists without any managed hook
    And the state of the repository is recorded
    When I install the local gate
    Then the exit code is 1
    And stderr contains "unmanaged"
    And nothing in the repository has changed since it was recorded
    And the owner's file is untouched
    And no pre-commit hook is installed

  Scenario Outline: A configured hooks path means a hook manager owns the hooks
    Given a repository without LeftBlock
    And git is configured with core.hooksPath "<hooks path>"
    And the state of the repository is recorded
    When I install the local gate
    Then the exit code is 1
    And stderr contains "core.hooksPath"
    And nothing in the repository has changed since it was recorded
    And no pre-commit hook is installed

    Examples:
      | hooks path   |
      | .husky/_     |
      | shared-hooks |

  Scenario: An empty hooks path still counts as a hook manager
    Given a repository without LeftBlock
    And git is configured with an empty core.hooksPath
    And the state of the repository is recorded
    When I install the local gate
    Then the exit code is 1
    And stderr contains "core.hooksPath"
    And nothing in the repository has changed since it was recorded
    And no pre-commit hook is installed

  Scenario: A global hooks path is respected too
    Given a repository without LeftBlock
    And a global git configuration sets core.hooksPath to "shared-hooks"
    And the state of the repository is recorded
    When I install the local gate
    Then the exit code is 1
    And stderr contains "core.hooksPath"
    And nothing in the repository has changed since it was recorded
    And the global git configuration is untouched
    And no pre-commit hook is installed

  Scenario Outline: An edited gate file is preserved
    Given a repository with LeftBlock installed as a local check-only gate
    And the managed local <part> has been edited by its owner
    And the state of the repository is recorded
    When I install the local gate
    Then the exit code is 1
    And stderr contains "edited or disabled"
    And nothing in the repository has changed since it was recorded

    Examples:
      | part   |
      | hook   |
      | policy |
      | rules  |
      | state  |

  Scenario: A disabled hook is preserved
    Given a repository with LeftBlock installed as a local check-only gate
    And the managed pre-commit hook has been disabled
    And the state of the repository is recorded
    When I install the local gate
    Then the exit code is 1
    And stderr contains "edited or disabled"
    And nothing in the repository has changed since it was recorded

  Scenario Outline: A symlinked gate file is never followed or replaced
    Given a repository with LeftBlock installed as a local check-only gate
    And the managed local <part> is a symlink to a file of the owner
    And the state of the repository is recorded
    When I install the local gate
    Then the exit code is 1
    And stderr contains "regular file"
    And nothing in the repository has changed since it was recorded
    And the owner's file is untouched

    Examples:
      | part   |
      | hook   |
      | policy |
      | rules  |
      | state  |

  Scenario: A missing scanner prevents installation
    Given a repository without LeftBlock
    And the state of the repository is recorded
    When I install the local gate with the scanner "/nonexistent-synthetic-gitleaks"
    Then the exit code is 1
    And stderr contains "Gitleaks"
    And nothing in the repository has changed since it was recorded
    And no pre-commit hook is installed

  # --- Installing receipt mode ----------------------------------------------

  Scenario: Receipt mode installs a commit-msg hook, defaults and a secret
    Given a repository without LeftBlock
    When I run "leftblock install"
    Then the exit code is 0
    And the commit-msg hook and its ownership state are installed
    And the commit-msg hook is executable and its ownership state is private
    And the recorded ownership matches the installed commit-msg hook
    And default policy files are written to the working tree
    And a signing secret exists that only its owner can read

  Scenario: The receipt-mode hook pins the installing interpreter and PATH
    Given a repository with LeftBlock installed in receipt mode
    Then the commit-msg hook runs LeftBlock with the installing interpreter
    And the commit-msg hook captures the PATH of the installation

  Scenario: Reinstalling receipt mode changes nothing when nothing differs
    Given a repository with LeftBlock installed in receipt mode
    And the state of the repository is recorded
    When I run "leftblock install"
    Then the exit code is 0
    And nothing in the repository has changed since it was recorded

  Scenario: Reinstalling receipt mode refreshes the captured PATH
    Given a repository with LeftBlock installed in receipt mode
    When I reinstall receipt mode with "/different-bin" first on the PATH
    Then the exit code is 0
    And the commit-msg hook captures a PATH that starts with "/different-bin"

  Scenario: Receipt mode installs once for all linked worktrees
    Given a repository without LeftBlock
    And a linked worktree "linked" of the repository
    And I work from the linked worktree "linked"
    When I run "leftblock install"
    Then the exit code is 0
    And the commit-msg hook and its ownership state are installed

  Scenario: The receipt-mode hook stamps a message under a minimal PATH
    Given a repository with LeftBlock installed in receipt mode
    When I run the commit-msg hook on a new message with a minimal PATH
    Then the exit code is 0
    And the message file carries a clean inspection receipt

  Scenario: Installing receipt mode needs a LeftBlock that can run the hook
    Given a repository without LeftBlock
    And the state of the repository is recorded
    When I install receipt mode from a Python environment without LeftBlock
    Then the exit code is 1
    And stderr contains "Install LeftBlock"
    And nothing in the repository has changed since it was recorded
    And no commit-msg hook or ownership state is installed
    And no signing secret has been created

  Scenario Outline: Receipt mode never replaces another commit-msg hook, even when told yes
    Given a repository without LeftBlock
    And <foreign hook>
    And the state of the repository is recorded
    When I install receipt mode answering yes to every question
    Then the exit code is 1
    And stderr contains "unmanaged"
    And nothing in the repository has changed since it was recorded
    And the owner's "commit-msg" hook is as the owner wrote it
    And LeftBlock has written no default policy files
    And no signing secret has been created

    Examples:
      | foreign hook                                                           |
      | the repository has its own "commit-msg" hook                           |
      | the repository has its own "commit-msg" hook that is not executable    |

  Scenario Outline: Receipt mode defers to a configured hooks path
    Given a repository without LeftBlock
    And git is configured with core.hooksPath "<hooks path>"
    And the state of the repository is recorded
    When I install receipt mode answering yes to every question
    Then the exit code is 1
    And stderr contains "core.hooksPath"
    And nothing in the repository has changed since it was recorded
    And no commit-msg hook or ownership state is installed
    And LeftBlock has written no default policy files
    And no signing secret has been created

    Examples:
      | hooks path   |
      | .husky/_     |
      | shared-hooks |

  Scenario: An empty hooks path counts as a hook manager in receipt mode
    Given a repository without LeftBlock
    And git is configured with an empty core.hooksPath
    And the state of the repository is recorded
    When I run "leftblock install"
    Then the exit code is 1
    And stderr contains "core.hooksPath"
    And nothing in the repository has changed since it was recorded
    And LeftBlock has written no default policy files

  Scenario: Receipt mode defers to a global hooks path
    Given a repository without LeftBlock
    And a global git configuration sets core.hooksPath to "shared-hooks"
    And the state of the repository is recorded
    When I run "leftblock install"
    Then the exit code is 1
    And stderr contains "core.hooksPath"
    And nothing in the repository has changed since it was recorded
    And the global git configuration is untouched
    And no commit-msg hook or ownership state is installed

  Scenario: An edited receipt-mode hook is preserved
    Given a repository with LeftBlock installed in receipt mode
    And the managed receipt hook has been edited by its owner
    And the state of the repository is recorded
    When I run "leftblock install"
    Then the exit code is 1
    And stderr contains "changed"
    And nothing in the repository has changed since it was recorded

  Scenario: A disabled receipt-mode hook is preserved
    Given a repository with LeftBlock installed in receipt mode
    And the managed receipt hook has been disabled
    And the state of the repository is recorded
    When I run "leftblock install"
    Then the exit code is 1
    And stderr contains "disabled"
    And nothing in the repository has changed since it was recorded

  Scenario Outline: A symlinked receipt-mode file is never followed
    Given a repository without LeftBlock
    And the receipt-mode <part> is a symlink to a file of the owner
    And the state of the repository is recorded
    When I run "leftblock install"
    Then the exit code is 1
    And stderr contains "regular file"
    And nothing in the repository has changed since it was recorded
    And the owner's file is untouched

    Examples:
      | part            |
      | commit-msg hook |
      | ownership state |

  Scenario: A commit-msg slot that holds a directory is left alone
    Given a repository without LeftBlock
    And the commit-msg hook slot holds a directory
    And the state of the repository is recorded
    When I run "leftblock install"
    Then the exit code is 1
    And stderr contains "regular file"
    And nothing in the repository has changed since it was recorded

  Scenario: A symlinked hooks directory is left alone
    Given a repository without LeftBlock
    And the git hooks directory is a symlink to another directory
    And the state of the repository is recorded
    When I run "leftblock install"
    Then the exit code is 1
    And stderr contains "regular directory"
    And nothing in the repository has changed since it was recorded

  Scenario Outline: Unusable ownership state is never overwritten
    Given a repository with LeftBlock installed in receipt mode
    And the receipt-mode ownership state is overwritten with <content>
    And the state of the repository is recorded
    When I run "leftblock install"
    Then the exit code is 1
    And nothing in the repository has changed since it was recorded

    Examples:
      | content         |
      | []              |
      | {invalid        |
      | {"version": 1}  |
