Feature: Custom checkers
  As a team with rules a generic scanner cannot know
  We want to run any command, or a Tactus procedure, as part of the inspection
  So that confidential client names or proprietary logic can be guarded by the same gate

  In receipt mode, .leftblock.yml lists the checkers. Gitleaks with the shipped
  ruleset is only the default. A command checker is any program: its exit code
  says whether it passed (success_codes, default 0), found something
  (finding_codes, default 1) or broke (anything else, an error that no
  passphrase or override can clear). A command may be handed the path of a
  temporary report file with the placeholder {report_file}; LeftBlock reads
  the report, shows files, rules, descriptions and line numbers, and never
  the matched text, then deletes the report. Tactus procedures work the same
  way at the level of passed, failed or broke. Every checker runs, and any one
  of them failing blocks the commit.

  Rule: Checkers named in the policy decide the verdict

  Background:
    Given a repository with LeftBlock installed in receipt mode
    And a staged file "fixture.txt" containing:
      """
      one
      two
      three
      four
      five
      six
      seven
      eight
      """
    And a checker script "exit_with.py" containing:
      """
      import sys
      sys.exit(int(sys.argv[1]))
      """

  # --- Exit codes ------------------------------------------------------------

  Scenario Outline: The exit code decides whether a command checker passed, found something or broke
    Given the checker policy is:
      """
      checkers:
        - name: exit-code-checker
          type: command
          command: $PYTHON $CHECKERS/exit_with.py <code>
      """
    When I run "leftblock check"
    Then the exit code is <result>

    Examples: with the default codes, 0 succeeds and 1 is a finding
      | code | result |
      | 0    | 0      |
      | 1    | 1      |
      | 2    | 2      |
      | 127  | 2      |

  Scenario Outline: A policy can name its own success and finding codes
    Given the checker policy is:
      """
      checkers:
        - name: exit-code-checker
          type: command
          command: $PYTHON $CHECKERS/exit_with.py <code>
          success_codes: [0, 3]
          finding_codes: [4]
      """
    When I run "leftblock check"
    Then the exit code is <result>

    Examples: 3 now succeeds alongside 0, 4 is the finding, and the old finding code 1 is an error
      | code | result |
      | 0    | 0      |
      | 3    | 0      |
      | 4    | 1      |
      | 1    | 2      |

  Scenario: A success code that is not 0 is signed as a clean result
    Given the checker policy is:
      """
      checkers:
        - name: exit-code-checker
          type: command
          command: $PYTHON $CHECKERS/exit_with.py 3
          success_codes: [0, 3]
          finding_codes: [1]
      """
    When I commit the staged files
    Then the commit succeeds
    And the latest commit message contains "Inspection-result: clean"

  Scenario: A finding from a command that gives no report shows no output from it
    Given a checker script "noisy.py" containing:
      """
      import sys
      print("raw-scanner-chatter")
      print("raw-scanner-chatter", file=sys.stderr)
      sys.exit(1)
      """
    And the checker policy is:
      """
      checkers:
        - name: noisy-checker
          type: command
          command: $PYTHON $CHECKERS/noisy.py
      """
    When I run "leftblock check"
    Then the exit code is 1
    And stderr contains "checker output suppressed"
    And neither stdout nor stderr shows "raw-scanner-chatter"

  Scenario: Every checker runs even when an earlier one finds something
    Given a checker script "marker.py" containing:
      """
      import os
      open(os.path.join(os.environ["HOME"], "..", "second-checker-ran"), "w").close()
      """
    And the checker policy is:
      """
      checkers:
        - name: first-checker
          type: command
          command: $PYTHON $CHECKERS/exit_with.py 1
        - name: second-checker
          type: command
          command: $PYTHON $CHECKERS/marker.py
      """
    When I run "leftblock check"
    Then the exit code is 1
    And the scratch file "second-checker-ran" exists

  # --- The report file -------------------------------------------------------

  Scenario: A report file is handed to the checker and its findings are shown without the matched text
    Given a checker script "report.py" containing:
      """
      import json, sys
      secret_text = "matched-" + "material"
      report = [{
          "File": "fixture.txt", "RuleID": "synthetic-rule", "StartLine": 7, "EndLine": 7,
          "Description": "Synthetic rule description",
          "Match": secret_text, "Secret": secret_text, "Line": secret_text,
          "Fingerprint": secret_text,
      }]
      open(sys.argv[1], "w").write(json.dumps(report))
      print(secret_text)
      print(secret_text, file=sys.stderr)
      sys.exit(1)
      """
    And the checker policy is:
      """
      checkers:
        - name: reporting-checker
          type: command
          command: $PYTHON $CHECKERS/report.py {report_file}
      """
    When I run "leftblock check"
    Then the exit code is 1
    And stderr contains "fixture.txt:7: synthetic-rule"
    And stderr contains "(Synthetic rule description)"
    And neither stdout nor stderr shows "matched-material"

  Scenario: A description in a report is cut to a safe length and stripped of escape codes
    Given a checker script "long_report.py" containing:
      """
      import json, sys
      report = [
          {"File": "fixture.txt", "RuleID": "long-rule", "StartLine": 1, "Description": "x" * 200},
          {"File": "fixture.txt", "RuleID": "hostile-rule", "StartLine": 2,
           "Description": "bad" + chr(27) + "[31m text"},
      ]
      open(sys.argv[1], "w").write(json.dumps(report))
      sys.exit(1)
      """
    And the checker policy is:
      """
      checkers:
        - name: reporting-checker
          type: command
          command: $PYTHON $CHECKERS/long_report.py {report_file}
      """
    When I run "leftblock check"
    Then the exit code is 1
    And the finding description shown is 80 characters long
    And stderr shows no terminal escape sequences

  Scenario: A report path containing spaces reaches the checker as a single argument and is removed afterwards
    Given the temporary directory is a private folder named "private reports with spaces"
    And a checker script "one_argument.py" containing:
      """
      import json, sys
      assert len(sys.argv) == 2, "report path was split into %d arguments" % len(sys.argv)
      report = [{"File": "fixture.txt", "RuleID": "synthetic-rule", "StartLine": 3}]
      open(sys.argv[1], "w").write(json.dumps(report))
      sys.exit(1)
      """
    And the checker policy is:
      """
      checkers:
        - name: spacious-checker
          type: command
          command: $PYTHON $CHECKERS/one_argument.py {report_file}
      """
    When I run "leftblock check"
    Then the exit code is 1
    And stderr contains "fixture.txt:3: synthetic-rule"
    And nothing is left in the private temporary folder

  Scenario: The report is removed even when the checker passes
    Given the temporary directory is a private folder named "reports"
    And the checker policy is:
      """
      checkers:
        - name: reporting-checker
          type: command
          command: $PYTHON $CHECKERS/exit_with.py 0 {report_file}
      """
    When I run "leftblock check"
    Then the exit code is 0
    And nothing is left in the private temporary folder

  # --- Tactus ----------------------------------------------------------------

  Scenario Outline: A Tactus procedure passes, fails or breaks according to its exit status
    Given a stand-in tactus program containing:
      """
      import sys
      print("tactus-private-log")
      print("tactus-private-log", file=sys.stderr)
      sys.exit(<code>)
      """
    And the checker policy is:
      """
      checkers:
        - name: client-name-scan
          type: tactus
          procedure: check_clients
      """
    When I run "leftblock check"
    Then the exit code is <result>
    And neither stdout nor stderr shows "tactus-private-log"

    Examples: 0 passes, 1 is a failure to approve, anything else is an error
      | code | result |
      | 0    | 0      |
      | 1    | 1      |
      | 2    | 2      |

  Scenario: A Tactus error is not a finding a person can approve
    Given a stand-in tactus program containing:
      """
      import sys
      sys.exit(2)
      """
    And the checker policy is:
      """
      checkers:
        - name: client-name-scan
          type: tactus
          procedure: check_clients
      """
    When On an interactive terminal I run "leftblock hook $MESSAGE_FILE" and enter the shared passphrase
    Then the exit code is 1
    And stderr contains "A checker could not complete"
    And stderr does not contain "approval passphrase"
    And the commit message file does not contain "Inspection-sig"

  Scenario: A Tactus failure can be approved by a person with the passphrase
    Given a stand-in tactus program containing:
      """
      import sys
      sys.exit(1)
      """
    And the checker policy is:
      """
      checkers:
        - name: client-name-scan
          type: tactus
          procedure: check_clients
      """
    When On an interactive terminal I run "leftblock hook $MESSAGE_FILE" and enter the shared passphrase
    Then the exit code is 0
    And the commit message file contains "Inspection-result: override:1-checkers"

  Scenario: A Tactus checker without a procedure is an invalid policy
    Given the checker policy reads "{checkers: [{name: client-name-scan, type: tactus}]}"
    When I run "leftblock check"
    Then the exit code is 2
    And stderr contains "Missing or invalid checker configuration"

  Scenario: During a merge Tactus sees the full staged tree while command checkers see only what the merge adds
    Given the history is on a branch called "trunk"
    And the file "fixture.txt" is committed
    And a branch "feature" is created from the current one and checked out
    And the current branch gains a commit adding "imported.txt" containing a synthetic harmless code
    And the branch "trunk" is checked out
    And the current branch gains a commit adding "trunk.txt" containing a synthetic harmless code
    And a merge of "feature" is in progress, not yet committed
    And a checker script "staged_files.py" containing:
      """
      import subprocess, sys
      names = subprocess.run(
          ["git", "diff", "--cached", "--name-only"], capture_output=True, text=True, check=True,
      ).stdout.split()
      sys.exit(1 if "imported.txt" in names else 0)
      """
    And a stand-in tactus program containing:
      """
      import subprocess, sys
      names = subprocess.run(
          ["git", "diff", "--cached", "--name-only"], capture_output=True, text=True, check=True,
      ).stdout.split()
      sys.exit(1 if "imported.txt" in names else 0)
      """
    And the checker policy is:
      """
      checkers:
        - name: command-scoped
          type: command
          command: $PYTHON $CHECKERS/staged_files.py
        - name: tactus-full-index
          type: tactus
          procedure: whole_tree
      """
    When I run "leftblock check"
    Then the exit code is 1
    And stderr contains "Checker "tactus-full-index" did not pass"
    And stderr does not contain "Checker "command-scoped" did not pass"

  Rule: The defaults written by installing are usable

  Scenario: Installing writes a default policy that runs Gitleaks with the shipped ruleset
    Given a repository without LeftBlock
    When I run "leftblock install"
    Then the exit code is 0
    And the file ".leftblock.yml" contains "gitleaks protect --staged"
    And the file ".leftblock.yml" contains ".leftblock/gitleaks.toml"
    And the file ".leftblock.yml" contains "finding_codes: [1]"
    And the file ".leftblock/gitleaks.toml" is identical to the packaged ruleset

  Scenario: Installing never overwrites a policy or ruleset the team already has
    Given a repository without LeftBlock
    And a staged file ".leftblock.yml" containing:
      """
      version: 1
      checkers: []
      """
    And a staged file ".leftblock/gitleaks.toml" containing:
      """
      # user-customized ruleset
      """
    When I run "leftblock install"
    Then the exit code is 0
    And the file ".leftblock.yml" still reads:
      """
      version: 1
      checkers: []
      """
    And the file ".leftblock/gitleaks.toml" still reads:
      """
      # user-customized ruleset
      """

  @gitleaks
  Scenario: The installed default policy is valid and usable straight away
    Given a repository without LeftBlock
    And a staged file "app.py" containing a synthetic harmless code
    When I run "leftblock install"
    And I run "leftblock check"
    Then the exit code is 0
    And stderr contains "All configured checks passed"
