Feature: AI provider API keys are blocked out of the box
  As a developer whose code calls AI provider APIs
  We want LeftBlock's shipped rules to recognise those providers' API keys
  So that a key pasted into code, config or a log never reaches a commit

  Scenario Outline: A pasted <provider> key is blocked even without a telling variable name
    Given a repository installed with leftblock defaults
    And a staged file containing a bare synthetic <provider> key
    When I commit the staged files
    Then the commit should be blocked
    And the block should name the rule <rule>
    And the block should not show the key
    And the block should advise rotating the key

    Examples:
      | provider       | rule                      |
      | OpenAI         | leftblock-openai-key      |
      | OpenAI admin   | leftblock-openai-key      |
      | Anthropic      | leftblock-anthropic-key   |
      | Groq           | leftblock-groq-key        |
      | xAI            | leftblock-xai-key         |
      | Replicate      | leftblock-replicate-key   |
      | Together AI    | leftblock-together-key    |
      | OpenRouter     | leftblock-openrouter-key  |
      | Fireworks      | leftblock-fireworks-key   |
      | Cerebras       | leftblock-cerebras-key    |
      | LangSmith      | leftblock-langsmith-key   |
      | ElevenLabs     | leftblock-elevenlabs-key  |
      | Voyage AI      | leftblock-voyage-key      |
      | Pinecone       | leftblock-pinecone-key    |

  Scenario Outline: A <provider> key with no fixed prefix is blocked when assigned to a provider-named variable
    Given a repository installed with leftblock defaults
    And a staged file assigning a synthetic <provider> key to <variable>
    When I commit the staged files
    Then the commit should be blocked
    And the block should name the rule leftblock-ai-provider-key-assignment
    And the block should not show the key

    Examples:
      | provider             | variable             |
      | Mistral              | MISTRAL_API_KEY      |
      | Cohere               | COHERE_API_KEY       |
      | Azure OpenAI         | AZURE_OPENAI_API_KEY |
      | Deepgram             | DEEPGRAM_API_KEY     |
      | Together AI (legacy) | TOGETHER_API_KEY     |

  Scenario Outline: References to a key and placeholders are not blocked
    Given a repository installed with leftblock defaults
    And a staged file containing the line "<line>"
    When I commit the staged files
    Then the commit should be allowed

    Examples:
      | line                                    |
      | OPENAI_API_KEY=${OPENAI_API_KEY}        |
      | key = os.environ["ANTHROPIC_API_KEY"]   |
      | MISTRAL_API_KEY=your-key-here           |
      | GROQ_API_KEY=<your-api-key>             |
      | pip install scikit-learn  # sk-learn    |
