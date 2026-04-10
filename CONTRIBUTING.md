# How to contribute

Patches are more than welcome at OpenCryptoki, be it to fix a bug or to add a
new feature. To make your life, and also our life, easy there are a few steps
that we need the contributors to follow.

## Getting started

* Read and study the current [PKCS #11 standard](https://www.oasis-open.org/committees/tc_home.php?wg_abbrev=pkcs11).
* Make sure you have a [GitHub account](https://github.com/signup/free)
* Submit a ticket for your issue, assuming one does not already exist.
  * Clearly describe the issue, including steps to reproduce when it is a bug.
  * Make sure you fill in the earliest version that you know has the issue.
  * In case of a bug, try to attach some logs. Enable tracing on OpenCryptoki by
    running `export OPENCRYPTOKI_TRACE_LEVEL=<level>`. For more information about
    trace level check the [FAQ](FAQ).
  * Include information from your environment (OS, gcc version, and any other
    related packages version).
  * In case of a new hardware token, please provide a way for us to have access
    to an environment that contains such hardware or a way to run automated tests
    through Jenkins or other similar tool.
  * In case AI assisted you to identify the issue, please state the name of the AI tool or framework.
* Fork the repository on GitHub.

## Making changes

* Create a topic/issue branch from the `master` branch.
* Please avoid working directly on the `master` branch.
* If the changes are too big, please separate it into smaller, logical, commits.
  This will improve commit history and code review.
* Follow the [coding style](doc/coding_style.md) guidelines.
* Check for unnecessary whitespace with `git diff --check` before committing.
* Make sure your commit messages are in the proper format and sign your patch
  to certify the Developer Certificate of Origin (DCO):

  ```text
  Add CONTRIBUTING guideline

  The CONTRIBUTING.md file describes the guidelines that every Contributor
  should follow to get their code integrated into OpenCryptoki. This will
  improve Contributors/Maintainers work.

  Signed-off-by: YOUR_NAME <youremail@something.com>
  ```

* AI agents MUST NOT add Signed-off-by tags. Only humans can legally
  certify the Developer Certificate of Origin (DCO).
  The human submitter is responsible for:
  * Reviewing all AI-generated code.
  * Ensuring compliance with licensing requirements.
  * Adding their own Signed-off-by tag to certify the Developer Certificate of Origin.
  * Taking full responsibility for the contribution.
* Make sure you have added the necessary tests for your changes.
* Run _all_ the tests to assure nothing else was accidentally broken. If you do
  not have the necessary hardware to run _all_ tests, please write it down to us,
  so we can manage to do the testing for you.

## Attribution

When AI tools contribute to openCryptoki, proper attribution helps
track the evolving role of AI in the development process.
Contributions should include an Assisted-by tag in the following format:

```text
Assisted-by: AGENT_NAME:MODEL_VERSION [TOOL1] [TOOL2]
```

Where:

* AGENT_NAME is the name of the AI tool or framework
* MODEL_VERSION is the specific model version used
* \[TOOL1\] \[TOOL2\] are optional specialized analysis tools used (e.g., coccinelle,
sparse, smatch, clang-tidy)

Basic development tools (git, gcc, make, editors) should not be listed.

## Submitting Changes

* Sign your commits, as mentioned above.
* Submit a pull request to the opencryptoki repository on opencryptoki organization.
* Include test information/results on the pull request.
* Wait for the Maintainers feedback about your changes. Although we are always
working on the project, sometimes we have our attention caught up on higher
priority tasks for the project.
* Be ready to answer any doubts that we might have about your changes, otherwise
if we do not get an answer we will not be able to merge your code.

## Final thoughts

* Feel free to ask questions, there is no such thing as a stupid question, just
stupid people.
* Have fun in the process, coding is fun!
