Feature: Stable runtime and upgrades
  As a developer with LeftBlock gates in several repositories
  I want every hook to run through one stable link to my installed LeftBlock
  So that upgrading LeftBlock once upgrades every repository, and a broken environment never lets a commit slip through

  When LeftBlock is installed from a virtual environment, installing the gate
  links $LEFTBLOCK_HOME/current to that environment and
  ~/.local/bin/leftblock to its command. Hooks name the link, not the
  environment, so reinstalling from a newer environment in any one repository
  repoints them all. Installation never replaces a file of yours or a
  directory where it expects a link. If the link breaks, the hook refuses to
  commit and says how to reinstall. Every scenario here runs with its own
  temporary home, so the real ~/.local is never touched.

  Scenario: Installing from a virtualenv links the runtime and the command
    Given a repository without LeftBlock
    And a runtime environment "alpha" with LeftBlock installed
    When I install the local gate from the runtime environment "alpha"
    Then the exit code is 0
    And the runtime link points to the environment "alpha"
    And the leftblock command in the user's bin directory links to the runtime
    And the install reports the new links
    And the hook runs LeftBlock through the runtime link

  Scenario: Reinstalling from the same environment reports no link changes
    Given a repository without LeftBlock
    And a runtime environment "alpha" with LeftBlock installed
    And the repository is guarded from the runtime environment "alpha"
    When I install the local gate from the runtime environment "alpha"
    Then the exit code is 0
    And the install reports no link changes
    And the runtime link points to the environment "alpha"

  @gitleaks
  Scenario: A commit is guarded through the runtime link
    Given a repository without LeftBlock
    And a runtime environment "alpha" with LeftBlock installed
    And the repository is guarded from the runtime environment "alpha"
    And a staged file "client.py" containing a synthetic OpenAI key
    When I commit the staged files
    Then the commit is blocked
    And HEAD has not moved
    And stderr contains "leftblock-openai-key"

  Scenario: Stale links are repointed to the new environment
    Given a repository without LeftBlock
    And a runtime environment "alpha" with LeftBlock installed
    And the runtime and command links already point to an old, missing runtime
    When I install the local gate from the runtime environment "alpha"
    Then the exit code is 0
    And the runtime link points to the environment "alpha"
    And the leftblock command in the user's bin directory links to the runtime

  Scenario: A script of the user's at the command location is never replaced
    Given a repository without LeftBlock
    And a runtime environment "alpha" with LeftBlock installed
    And the user has their own script at the command location
    When I install the local gate from the runtime environment "alpha"
    Then the exit code is 0
    And the user's own script is untouched
    And the installer warns that it left the user's script alone
    And the runtime link points to the environment "alpha"
    And the hook runs LeftBlock through the runtime link

  Scenario: A runtime location that is not a symlink is refused
    Given a repository without LeftBlock
    And a runtime environment "alpha" with LeftBlock installed
    And the runtime link location holds a directory
    When I install the local gate from the runtime environment "alpha"
    Then the exit code is 1
    And stderr contains "not a symlink"
    And no command link exists
    And no hook, policy, rules or state were written

  Scenario: Upgrading in one repository repoints every repository
    Given a repository without LeftBlock
    And a runtime environment "alpha" with LeftBlock installed
    And a runtime environment "beta" with LeftBlock installed
    And the repository is guarded from the runtime environment "alpha"
    And another repository "second" guarded from the runtime environment "alpha"
    When I install the local gate from the runtime environment "beta"
    Then the exit code is 0
    And the runtime link points to the environment "beta"
    And the hooks of every repository are exactly as they were installed

  @gitleaks
  Scenario: After an upgrade another repository is guarded by the new environment
    Given a repository without LeftBlock
    And a runtime environment "alpha" with LeftBlock installed
    And a runtime environment "beta" with LeftBlock installed
    And the repository is guarded from the runtime environment "alpha"
    And another repository "second" guarded from the runtime environment "alpha"
    And I install the local gate from the runtime environment "beta"
    And a staged file "client.py" containing a synthetic OpenAI key
    When I commit the staged files
    Then the commit is blocked
    And stderr contains "leftblock-openai-key"

  Scenario: Outside a virtualenv the hook keeps the interpreter and makes no links
    Given a repository without LeftBlock
    When I install the local gate from an interpreter outside any virtualenv
    Then the exit code is 0
    And the hook runs LeftBlock with the installing interpreter directly
    And no runtime link and no command link exist

  Scenario: A broken runtime link makes the hook fail closed with reinstall instructions
    Given a repository without LeftBlock
    And a runtime environment "alpha" with LeftBlock installed
    And the repository is guarded from the runtime environment "alpha"
    And the runtime link points to a path that does not exist
    When I run the pre-commit hook directly
    Then the hook fails with a reinstall message naming the missing interpreter

  Scenario: A broken runtime link blocks the commit
    Given a repository without LeftBlock
    And a runtime environment "alpha" with LeftBlock installed
    And the repository is guarded from the runtime environment "alpha"
    And the runtime link points to a path that does not exist
    And a staged file "app.py" containing a synthetic harmless code
    When I commit the staged files
    Then the commit is blocked
    And HEAD has not moved
    And stderr contains "Reinstall:"
