@gitleaks
Feature: Reading a block
  As a developer whose commit was just stopped
  I want the report to tell me what was found, where, why and what to do next
  So that I can fix it in one pass, or clear a false alarm, without guessing and without the report leaking the very thing it caught

  A blocked commit prints one report on standard error. It opens with the
  LeftBlock version and a hash of the ruleset that ran, so a report says
  exactly which rules were applied. Each finding is a line reading
  file:LINE: rule [id ...] (description), followed by one hint per rule.
  The matched value is never printed. The last line is an ERROR line that
  stands alone: tools that wrap git often show only that line, so it names
  every finding and the next step, including the exact command for a
  recorded override. Printed commands never contain the home directory, and
  no colour codes appear unless a person is looking at a terminal.

  Scenario: The report opens with the version and the ruleset hash
    Given a repository with LeftBlock installed as a local check-only gate
    And a staged file "page.tsx" containing a synthetic personal email
    When I run "leftblock check"
    Then the exit code is 1
    And the first line of stderr names the installed version and the ruleset hash

  Scenario: A blocked commit prints the same report as a check
    Given a repository with LeftBlock installed as a local check-only gate
    And a staged file "page.tsx" containing a synthetic personal email
    When I commit the staged files
    Then the commit is blocked
    And the first line of stderr names the installed version and the ruleset hash
    And stderr contains "leftblock-personal-email"

  Scenario: The ruleset is unknown when the scanner is not given a rules file
    Given a repository without LeftBlock
    And the repository policy runs gitleaks without a rules file
    And a staged file "settings.py" containing a synthetic AWS key pair
    When I run "leftblock check"
    Then the exit code is 1
    And the first line of stderr names the installed version and the ruleset as unknown

  Scenario: Each finding reads file, line, rule, id and description
    Given a repository with LeftBlock installed as a local check-only gate
    And a staged file "page.tsx" containing:
      """
      first line is harmless
      """
    And the file "page.tsx" gets a synthetic personal email appended and staged
    When I run "leftblock check"
    Then the exit code is 1
    And stderr lists "leftblock-personal-email" for "page.tsx" at line 2 described as "Personal email address"
    And every listed finding carries an id of sixteen hexadecimal characters

  Scenario: Line numbers are right inside a modified committed file
    Given a repository with LeftBlock installed as a local check-only gate
    And a staged file "notes.txt" containing:
      """
      one
      two
      three
      """
    And the file "notes.txt" is committed
    And the file "notes.txt" gets a synthetic personal email appended and staged
    When I run "leftblock check"
    Then the exit code is 1
    And stderr lists "leftblock-personal-email" for "notes.txt" at line 4

  Scenario: A long rule description is cut to eighty characters
    Given a repository without LeftBlock
    And a scanner reports a finding with a description of 200 characters
    And a staged file "page.txt" containing:
      """
      harmless
      """
    When I run "leftblock check"
    Then the exit code is 1
    And stderr lists "scripted-rule" for "page.txt" at line 1
    And stderr shows a description of exactly 80 "x" characters

  Scenario: A description cannot drive the terminal
    Given a repository without LeftBlock
    And a scanner reports a finding whose description contains a terminal escape sequence
    And a staged file "page.txt" containing:
      """
      harmless
      """
    When I run "leftblock check"
    Then the exit code is 1
    And stderr lists "scripted-rule" for "page.txt" at line 1
    And stderr contains no terminal escape characters

  Scenario: Whatever the scanner printed or matched is never shown
    Given a repository without LeftBlock
    And a scanner reports a finding with a description of 10 characters
    And a staged file "page.txt" containing:
      """
      harmless
      """
    When I run "leftblock check"
    Then the exit code is 1
    And the output does not reveal the synthetic value

  Scenario Outline: The matched <kind> is never shown
    Given a repository with LeftBlock installed as a local check-only gate
    And a staged file "data.txt" containing a synthetic <kind>
    When I run "leftblock check"
    Then the exit code is 1
    And the output does not reveal the synthetic value

    Examples:
      | kind                 |
      | personal email       |
      | home path            |
      | session UUID         |
      | AWS key pair         |
      | OpenAI key           |
      | Ethereum private key |
      | seed phrase          |

  Scenario Outline: A <kind> finding is followed by the advice for its rule
    Given a repository with LeftBlock installed as a local check-only gate
    And a staged file "data.txt" containing a synthetic <kind>
    When I run "leftblock check"
    Then the exit code is 1
    And stderr contains "<advice>"

    Examples:
      | kind                 | advice                                          |
      | personal email       | reserved placeholder                            |
      | home path            | Use a relative path, $HOME or ~ instead.        |
      | Windows home path    | Use a relative path, $HOME or ~ instead.        |
      | session UUID         | Drop the identifier or describe it instead.     |
      | actor id             | Drop the identifier or describe it instead.     |
      | OpenAI key           | Remove it AND rotate the key                    |
      | Anthropic key        | Remove it AND rotate the key                    |
      | Ethereum private key | Remove it AND rotate the key                    |
      | Bitcoin WIF key      | Remove it AND rotate the key                    |
      | seed phrase          | Remove it AND rotate the key                    |

  Scenario: A rule without advice of its own prints no hint
    Given a repository with LeftBlock installed as a local check-only gate
    And a staged file "settings.py" containing a synthetic AWS key pair
    When I run "leftblock check"
    Then the exit code is 1
    And stderr does not contain "Hint:"

  Scenario: The advice for a rule is printed once however many findings it has
    Given a repository with LeftBlock installed as a local check-only gate
    And a staged file "one.md" containing a synthetic home path
    And a staged file "two.md" containing a synthetic Linux home path
    When I run "leftblock check"
    Then the exit code is 1
    And stderr shows "Hint: Use a relative path" 1 time

  Scenario: Different rules each print their own advice
    Given a repository with LeftBlock installed as a local check-only gate
    And a staged file "one.md" containing a synthetic home path
    And a staged file "two.md" containing a synthetic personal email
    When I run "leftblock check"
    Then the exit code is 1
    And stderr shows "Hint: Use a relative path" 1 time
    And stderr shows "Hint: Use a role address" 1 time

  Scenario: The last line alone names every finding and the next step
    Given a repository with LeftBlock installed as a local check-only gate
    And a staged file "one.md" containing a synthetic personal email
    And a staged file "two.md" containing a synthetic home path
    When I run "leftblock check"
    Then the exit code is 1
    And the last line of stderr starts with the ERROR label "Inspection blocked"
    And the last line of stderr names every listed finding by rule, file, line and id
    And the last line of stderr contains "Remove the flagged content"
    And the last line of stderr offers the allow command for every listed id

  Scenario: The allow command in the report is the exact command to run
    Given a repository with LeftBlock installed as a local check-only gate
    And a staged file "page.tsx" containing a synthetic personal email
    When I run "leftblock check"
    Then stderr contains "record a reviewed override"
    And stderr contains "--reason"
    And the last line of stderr offers the allow command for every listed id

  Scenario: Printed commands use the short name when LeftBlock is on the command path
    Given a repository with LeftBlock installed as a local check-only gate
    And LeftBlock is on the command path
    And a staged file "page.tsx" containing a synthetic personal email
    When I run "leftblock check"
    Then the exit code is 1
    And the printed commands begin with "leftblock"

  Scenario: Printed commands never contain the home directory
    Given a repository with LeftBlock installed as a local check-only gate
    And LeftBlock is not on the command path and the interpreter lives under the home directory
    And a staged file "page.tsx" containing a synthetic personal email
    When I run "leftblock check"
    Then the exit code is 1
    And no line of stderr contains the home directory
    And the printed commands show the interpreter path with the home directory as a tilde
    And the last line of stderr contains " allow "

  Scenario: Captured output carries no colour codes
    Given a repository with LeftBlock installed as a local check-only gate
    And NO_COLOR is not set
    And a staged file "page.tsx" containing a synthetic personal email
    When I run "leftblock check"
    Then the exit code is 1
    And stderr contains no terminal escape characters

  Scenario: NO_COLOR keeps the report plain
    Given a repository with LeftBlock installed as a local check-only gate
    And NO_COLOR is set
    And a staged file "page.tsx" containing a synthetic personal email
    When I run "leftblock check"
    Then the exit code is 1
    And stderr contains no terminal escape characters

  Scenario: A root .gitleaksignore is called out on a blocked check
    Given a repository with LeftBlock installed as a local check-only gate
    And a root .gitleaksignore file exists
    And a staged file "page.tsx" containing a synthetic personal email
    When I run "leftblock check"
    Then the exit code is 1
    And stderr contains "This repository has a root .gitleaksignore"
    And stderr contains "prefer leftblock allow for new exceptions"

  Scenario: A root .gitleaksignore is called out even when the check passes
    Given a repository with LeftBlock installed as a local check-only gate
    And a root .gitleaksignore file exists
    And a staged file "app.py" containing a synthetic harmless code
    When I run "leftblock check"
    Then the exit code is 0
    And stderr contains "This repository has a root .gitleaksignore"
