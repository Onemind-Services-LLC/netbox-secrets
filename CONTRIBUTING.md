# CONTRIBUTING

## Reporting Bugs

* First, ensure that you're running the [latest stable version](https://github.com/netbox-community/netbox/releases)
of NetBox or this plugin [latest stable version](https://github.com/Onemind-Services-LLC/netbox-secrets/releases).
If you're running an older version, it's possible that the bug has already been fixed
or you are running a version of the plugin not tested with the NetBox version
you are running [Compatibility Matrix](./README.md#compatibility).

* Next, check the GitHub [issues list](https://github.com/Onemind-Services-LLC/netbox-secrets/issues)
to see if the bug you've found has already been reported. If you think you may
be experiencing a reported issue that hasn't already been resolved, please
click "add a reaction" in the top right corner of the issue and add a thumbs
up (+1). You might also want to add a comment describing how it's affecting your
installation. This will allow us to prioritize bugs based on how many users are
affected.

* When submitting an issue, please be as descriptive as possible. Be sure to
provide all information request in the issue template, including:

  * The environment in which NetBox is running
  * The exact steps that can be taken to reproduce the issue
  * Expected and observed behavior
  * Any error messages generated
  * Screenshots (if applicable)

## Feature Requests

* First, check the GitHub [issues list](https://github.com/Onemind-Services-LLC/netbox-secrets/issues)
to see if the feature you're requesting is already listed. (Be sure to search
closed issues as well, since some feature requests have been rejected.) If the
feature you'd like to see has already been requested and is open, click "add a
reaction" in the top right corner of the issue and add a thumbs up (+1). This
ensures that the issue has a better chance of receiving attention. Also feel
free to add a comment with any additional justification for the feature.
(However, note that comments with no substance other than a "+1" will be
deleted. Please use GitHub's reactions feature to indicate your support.)

* Good feature requests are very narrowly defined. Be sure to thoroughly
describe the functionality and data model(s) being proposed. The more effort
you put into writing a feature request, the better its chance is of being
implemented. Overly broad feature requests will be closed.

* When submitting a feature request on GitHub, be sure to include all
information requested by the issue template, including:

  * A detailed description of the proposed functionality
  * A use case for the feature; who would use it and what value it would add
    to NetBox
  * A rough description of changes necessary to the database schema (if
    applicable)
  * Any third-party libraries or other resources which would be involved

## Submitting Pull Requests

* Be sure to open an issue **before** starting work on a pull request, and
discuss your idea with the NetBox maintainers before beginning work. This will
help prevent wasting time on something that might we might not be able to
implement. When suggesting a new feature, also make sure it won't conflict with
any work that's already in progress.

* Once you've opened or identified an issue you'd like to work on, ask that it
be assigned to you so that others are aware it's being worked on. A maintainer
will then mark the issue as "accepted."

* Any pull request which does _not_ relate to an **accepted** issue will be closed.

* All new functionality must include relevant tests where applicable.

* When submitting a pull request, please be sure to work off of the `dev`
branch, rather than `master`. The `dev` branch is used for ongoing
development, while `master` is used for tagging stable releases.

* In most cases, it is not necessary to add a changelog entry: A maintainer will
take care of this when the PR is merged. (This helps avoid merge conflicts
resulting from multiple PRs being submitted simultaneously.)

* All code submissions should meet the following criteria (CI will enforce
these checks):

  * Syntax Checks
  * Linting
  * Unit Tests

## Commenting

Only comment on an issue if you are sharing a relevant idea or constructive
feedback. **Do not** comment on an issue just to show your support (give the
top post a :+1: instead) or ask for an ETA. These comments will be deleted to
reduce noise in the discussion.
