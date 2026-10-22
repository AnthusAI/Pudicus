Feature: Failing closed
  As a security-minded team
  We want LeftBlock to block a commit whenever it cannot be sure the commit was inspected
  So that a broken policy, a missing scanner or a confused checker can never wave sensitive data through

  An inspection only counts when it completes. If the policy is absent, empty
  or malformed, if a checker is unknown, missing, crashes or reports nonsense,
  or if the staged files change while they are being inspected, the commit is
  blocked, no receipt is written and HEAD stays where it was. These are
  operational errors, not findings, so no passphrase or recorded override can
  clear them, and the scanner's own logs are never shown because they may
  contain the very data being protected. Only what is staged is inspected:
  the working copy, which may differ, is never consulted.

  Background:
    Given a repository with LeftBlock installed in receipt mode
    And a staged file "fixture.txt" containing:
      """
      Harmless staged data.
      """

  # --- The policy ----------------------------------------------------------

  Scenario: A commit with no policy file is blocked
    Given there is no checker policy
    When I commit the staged files
    Then the commit is blocked
    And HEAD has not moved
    And stderr does not contain "Inspection-sig"

  Scenario: A commit with an empty policy file is blocked
    Given the checker policy is empty
    When I commit the staged files
    Then the commit is blocked
    And HEAD has not moved

  Scenario Outline: A policy that cannot be understood blocks the commit
    Given the checker policy reads "<policy>"
    When I commit the staged files
    Then the commit is blocked
    And HEAD has not moved

    Examples: a policy that names no usable checker
      | policy                                         |
      | {version: 1, checkers: []}                     |
      | checkers: [                                    |
      | []                                             |
      | {checkers: [{type: command, command: 'true'}, 5]} |

  Scenario: A broken policy is explained to the person committing, without a stack trace
    Given there is no checker policy
    When I commit the staged files
    Then the commit is blocked
    And stderr contains "Missing or invalid checker configuration"
    And stderr does not contain "Traceback"

  Scenario: The dry run reports a missing policy as an error, not as a pass
    Given there is no checker policy
    When I run "leftblock check"
    Then the exit code is 2
    And stderr contains "Missing or invalid checker configuration"

  Scenario Outline: A checker definition LeftBlock does not recognise blocks the commit
    Given the checker policy reads "<policy>"
    When I commit the staged files
    Then the commit is blocked
    And HEAD has not moved

    Examples: an unknown type, overlapping exit codes, and no command
      | policy                                                                         |
      | {checkers: [{type: unrecognized, command: 'true'}]}                           |
      | {checkers: [{type: command, command: 'true', success_codes: [0, 1]}]}         |
      | {checkers: [{type: command, command: 'true', finding_codes: [0, 1]}]}         |
      | {checkers: [{type: command, command: ''}]}                                    |

  # --- The scanner ---------------------------------------------------------

  Scenario: A scanner that is not installed blocks the commit
    Given the checker policy is:
      """
      checkers:
        - name: absent-scanner
          type: command
          command: $SCRATCH/no-such-scanner
      """
    When I commit the staged files
    Then the commit is blocked
    And HEAD has not moved
    And stderr contains "could not run"

  Scenario: A scanner that crashes blocks the commit and its logs are never shown
    Given a checker script "crashing.py" containing:
      """
      import sys
      print("private-diagnostic-text")
      print("private-diagnostic-text", file=sys.stderr)
      sys.exit(2)
      """
    And the checker policy is:
      """
      checkers:
        - name: crashing-scanner
          type: command
          command: $PYTHON $CHECKERS/crashing.py
      """
    When I commit the staged files
    Then the commit is blocked
    And HEAD has not moved
    And stderr contains "output suppressed"
    And neither stdout nor stderr shows "private-diagnostic-text"

  Scenario: A scanner that reports failure with an empty report is an operational error
    Given a checker script "empty_report.py" containing:
      """
      import sys
      open(sys.argv[1], "w").write("[]")
      sys.exit(1)
      """
    And the checker policy is:
      """
      checkers:
        - name: empty-report-scanner
          type: command
          command: $PYTHON $CHECKERS/empty_report.py {report_file}
      """
    When I run "leftblock check"
    Then the exit code is 2
    And stderr contains "no override is available"

  Scenario: A scanner whose report is unreadable blocks the commit and its contents are never shown
    Given a checker script "garbled_report.py" containing:
      """
      import sys
      open(sys.argv[1], "w").write("garbled-report-text")
      print("garbled-report-text")
      sys.exit(1)
      """
    And the checker policy is:
      """
      checkers:
        - name: garbled-report-scanner
          type: command
          command: $PYTHON $CHECKERS/garbled_report.py {report_file}
      """
    When I commit the staged files
    Then the commit is blocked
    And HEAD has not moved
    And stderr contains "output suppressed"
    And neither stdout nor stderr shows "garbled-report-text"

  Scenario: Files that change while they are being inspected block the commit
    Given a checker script "tamper.py" containing:
      """
      import subprocess
      open("fixture.txt", "w").write("Changed during inspection.\n")
      subprocess.run(["git", "add", "fixture.txt"], check=True)
      """
    And the checker policy is:
      """
      checkers:
        - name: tampering-scanner
          type: command
          command: $PYTHON $CHECKERS/tamper.py
      """
    When I commit the staged files
    Then the commit is blocked
    And HEAD has not moved
    And stderr contains "Staged tree changed during inspection"
    And stderr does not contain "Inspection-sig"

  Scenario: The dry run also refuses a result for files that changed during inspection
    Given a checker script "tamper.py" containing:
      """
      import subprocess
      open("fixture.txt", "w").write("Changed during inspection.\n")
      subprocess.run(["git", "add", "fixture.txt"], check=True)
      """
    And the checker policy is:
      """
      checkers:
        - name: tampering-scanner
          type: command
          command: $PYTHON $CHECKERS/tamper.py
      """
    When I run "leftblock check"
    Then the exit code is 2
    And stderr contains "Staged tree changed during inspection"

  Scenario: A commit cannot be signed without the shared secret
    Given the signing secret has been removed
    And the checker policy is:
      """
      checkers:
        - name: always-clean
          type: command
          command: $PYTHON -c pass
      """
    When I commit the staged files
    Then the commit is blocked
    And HEAD has not moved
    And stderr contains "Shared secret not found"

  # --- No override for errors ----------------------------------------------

  Scenario: An operational error cannot be approved with the passphrase
    Given a checker script "crashing.py" containing:
      """
      import sys
      sys.exit(2)
      """
    And the checker policy is:
      """
      checkers:
        - name: crashing-scanner
          type: command
          command: $PYTHON $CHECKERS/crashing.py
      """
    When On an interactive terminal I run "leftblock hook $MESSAGE_FILE" and enter the shared passphrase
    Then the exit code is 1
    And stderr contains "A checker could not complete"
    And stderr does not contain "approval passphrase"
    And the commit message file does not contain "Inspection-sig"

  # --- Only the staged content counts --------------------------------------

  @gitleaks
  Scenario: A sensitive commit is stopped before HEAD changes
    Given a staged file "client.py" containing a synthetic OpenAI key
    When I commit the staged files
    Then the commit is blocked
    And HEAD has not moved
    And stderr contains "leftblock-openai-key"
    And the output does not reveal the synthetic value

  @gitleaks
  Scenario: A sensitive staged file blocks the commit even if the working copy is clean
    Given a staged file "client.py" containing a synthetic OpenAI key
    And the working copy of "client.py" is replaced with harmless text, leaving the staged version alone
    When I commit the staged files
    Then the commit is blocked
    And HEAD has not moved

  @gitleaks
  Scenario: A clean staged file passes even if the working copy holds a secret
    Given a staged file "client.py" containing a synthetic harmless code
    And the working copy of "client.py" is replaced with a synthetic OpenAI key, leaving the staged version alone
    When I commit the staged files
    Then the commit succeeds
    And the latest commit message contains "Inspection-result: clean"

  @gitleaks
  Scenario: The dry run blocks a sensitive staged file without needing the signing secret
    Given a staged file "client.py" containing a synthetic OpenAI key
    And the signing secret has been removed
    When I run "leftblock check"
    Then the exit code is 1
    And stderr contains "leftblock-openai-key"
    And no signing secret exists
    And HEAD has not moved

  @gitleaks
  Scenario: The dry run of a clean commit needs no secret and writes no receipt
    Given a staged file "app.py" containing a synthetic harmless code
    And the signing secret has been removed
    When I run "leftblock check"
    Then the exit code is 0
    And no signing secret exists
    And HEAD has not moved
