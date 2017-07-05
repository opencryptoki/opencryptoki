# How to contribute

Patches are more than welcome at OpenCryptoki, be it to fix a bug or to add a
new feature. To make your life, and also our life, easy there are a few steps
that we need the contributors to follow.

## Getting started 

* Read and study the [PKCS #11 standard](https://www.oasis-open.org/committees/tc_home.php?wg_abbrev=pkcs11) v2.20 or, preferably, v2.40.
* Make sure to subscribe to our [technical discussion mailing-list](https://sourceforge.net/projects/opencryptoki/lists/opencryptoki-tech)
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
* Fork the repository on GitHub.

## Making changes
* Create a topic/issue branch from the `master` branch.
* Please avoid working directly on the `master` branch.
* If the changes are too big, please separate it into smaller, logical, commits.
This will improve commit history and code review.
* Follow the [coding style](doc/coding_style.md) guidelines.
* Check for unnecessary whitespace with `git diff --check` before committing.
* Make sure your commit messages are in the proper format and sign your patch:
```
    Add CONTRIBUTING guideline

    The CONTRIBUTING.md file describes the guidelines that every Contributor
    should follow to get their code integrated into OpenCryptoki. This will
    improve Contributors/Maintainers work.

    Signed-off-by: YOUR_NAME <youremail@something.com>
```

* Make sure you have added the necessary tests for your changes.
* Run _all_ the tests to assure nothing else was accidentally broken. If you do
not have the necessary hardware to run _all_ tests, please write it down to us,
so we can manage to do the testing for you.

## Submitting Changes

* Sign your commits, as mentioned above.
* There are two ways to submit patches:
  * If you prefer the old school way of sending patches to a mailing-list, then
  feel free to send your patch to the [technical discussion mailing-list](https://sourceforge.net/projects/opencryptoki/lists/opencryptoki-tech) . We will keep you posted as the code review goes by.
  * If you like GitHub and all the tools it has, then submit a pull request to
  * the opencryptoki repository on opencryptoki organization.
* Include test information/results on the email thread of your patch or on the
pull request.
* Wait for the Maintainers feedback about your changes. Although we are always
working on the project, sometimes we have our attention caught up on higher
priority tasks for the project.
* Be ready to answer any doubts that we might have about your changes, otherwise
if we do not get an answer we will not be able to merge your code.

## Final thoughts

* Feel free to ask questions, there is no such thing as a stupid question, just
stupid people.
* You can find us on the mailing list mentioned above.
* Have fun in the process, coding is fun!
