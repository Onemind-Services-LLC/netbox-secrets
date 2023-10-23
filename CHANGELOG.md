# Changelog

## [v1.9.0](https://github.com/Onemind-Services-LLC/netbox-secrets/tree/v1.9.0) (2023-09-07)

[Full Changelog](https://github.com/Onemind-Services-LLC/netbox-secrets/compare/v1.8.5...v1.9.0)

**Closed issues:**

- \[Feature\]: Add support for NetBox v3.6 [\#95](https://github.com/Onemind-Services-LLC/netbox-secrets/issues/95)
- \[Bug\]: Unable to add secrets in netbox through the API using a python script  [\#93](https://github.com/Onemind-Services-LLC/netbox-secrets/issues/93)
- \[Bug\]: Unable to view secrets in netbox web ui \(3.5.4 / 1.8.3 + 1.8.5\) [\#81](https://github.com/Onemind-Services-LLC/netbox-secrets/issues/81)
- \[Bug\]: Session Key is needed for API POSTS and no field is declared for this and Session Key is null when retrieved from API [\#80](https://github.com/Onemind-Services-LLC/netbox-secrets/issues/80)
- \[Feature\]: Add clone button for secret object view [\#78](https://github.com/Onemind-Services-LLC/netbox-secrets/issues/78)
- \[Bug\]: Adding Secrets is not appearing  [\#77](https://github.com/Onemind-Services-LLC/netbox-secrets/issues/77)
- \[Bug\]: /get-session-key/ does not accept query string parameter ?preserve\_key=True any more [\#65](https://github.com/Onemind-Services-LLC/netbox-secrets/issues/65)
- \[Feature\]: Add options to add certificates to device/store [\#32](https://github.com/Onemind-Services-LLC/netbox-secrets/issues/32)

**Merged pull requests:**

- Prepare for release [\#98](https://github.com/Onemind-Services-LLC/netbox-secrets/pull/98) ([abhi1693](https://github.com/abhi1693))
- Add support for NetBox v3.6 [\#97](https://github.com/Onemind-Services-LLC/netbox-secrets/pull/97) ([kprince28](https://github.com/kprince28))
- Bump word-wrap from 1.2.3 to 1.2.4 in /netbox\_secrets/project-static [\#86](https://github.com/Onemind-Services-LLC/netbox-secrets/pull/86) ([dependabot[bot]](https://github.com/apps/dependabot))
- Bump semver from 6.3.0 to 6.3.1 in /netbox\_secrets/project-static [\#84](https://github.com/Onemind-Services-LLC/netbox-secrets/pull/84) ([dependabot[bot]](https://github.com/apps/dependabot))

## [v1.8.5](https://github.com/Onemind-Services-LLC/netbox-secrets/tree/v1.8.5) (2023-06-19)

[Full Changelog](https://github.com/Onemind-Services-LLC/netbox-secrets/compare/v1.8.4...v1.8.5)

**Merged pull requests:**

- Fix migration to skip deleted devices and virtual machines [\#75](https://github.com/Onemind-Services-LLC/netbox-secrets/pull/75) ([kprince28](https://github.com/kprince28))

## [v1.8.4](https://github.com/Onemind-Services-LLC/netbox-secrets/tree/v1.8.4) (2023-06-12)

[Full Changelog](https://github.com/Onemind-Services-LLC/netbox-secrets/compare/v1.8.3...v1.8.4)

**Closed issues:**

- \[Bug\]: Migration Failure due to previous bug [\#73](https://github.com/Onemind-Services-LLC/netbox-secrets/issues/73)

**Merged pull requests:**

- Prepare for release [\#74](https://github.com/Onemind-Services-LLC/netbox-secrets/pull/74) ([kprince28](https://github.com/kprince28))
- Fix copy of data in migration [\#72](https://github.com/Onemind-Services-LLC/netbox-secrets/pull/72) ([kprince28](https://github.com/kprince28))

## [v1.8.3](https://github.com/Onemind-Services-LLC/netbox-secrets/tree/v1.8.3) (2023-06-02)

[Full Changelog](https://github.com/Onemind-Services-LLC/netbox-secrets/compare/v1.8.2...v1.8.3)

**Closed issues:**

- \[Bug\]: API get /secret-roles/?name=XXX doesn't work [\#68](https://github.com/Onemind-Services-LLC/netbox-secrets/issues/68)
- \[Bug\]: netbox-secrets 1.8.2 break netbox  [\#67](https://github.com/Onemind-Services-LLC/netbox-secrets/issues/67)
- \[Feature\]: Add the possibility of permissions to different groups/users keys as appropriate [\#62](https://github.com/Onemind-Services-LLC/netbox-secrets/issues/62)
- \[Feature\]: Add ability to link the device with secrets to click and connect [\#33](https://github.com/Onemind-Services-LLC/netbox-secrets/issues/33)

**Merged pull requests:**

- Prepare for release [\#70](https://github.com/Onemind-Services-LLC/netbox-secrets/pull/70) ([abhi1693](https://github.com/abhi1693))
- Fix secret role filterset [\#69](https://github.com/Onemind-Services-LLC/netbox-secrets/pull/69) ([kprince28](https://github.com/kprince28))

## [v1.8.2](https://github.com/Onemind-Services-LLC/netbox-secrets/tree/v1.8.2) (2023-05-25)

[Full Changelog](https://github.com/Onemind-Services-LLC/netbox-secrets/compare/v1.8.1...v1.8.2)

**Closed issues:**

- \[Bug\]: Deleting assigned object doesn't delete secret [\#61](https://github.com/Onemind-Services-LLC/netbox-secrets/issues/61)
- \[Bug\]: Decryption fails even with valid session key [\#60](https://github.com/Onemind-Services-LLC/netbox-secrets/issues/60)
- \[Bug\]: Failed to build docker image [\#58](https://github.com/Onemind-Services-LLC/netbox-secrets/issues/58)

**Merged pull requests:**

- PRVB [\#66](https://github.com/Onemind-Services-LLC/netbox-secrets/pull/66) ([abhi1693](https://github.com/abhi1693))
- \[Fix\]: The session wasn't working for other users [\#64](https://github.com/Onemind-Services-LLC/netbox-secrets/pull/64) ([kprince28](https://github.com/kprince28))

## [v1.8.1](https://github.com/Onemind-Services-LLC/netbox-secrets/tree/v1.8.1) (2023-05-08)

[Full Changelog](https://github.com/Onemind-Services-LLC/netbox-secrets/compare/v1.8.0...v1.8.1)

**Merged pull requests:**

- Handled operational error during collectstatic [\#59](https://github.com/Onemind-Services-LLC/netbox-secrets/pull/59) ([abhi1693](https://github.com/abhi1693))

## [v1.8.0](https://github.com/Onemind-Services-LLC/netbox-secrets/tree/v1.8.0) (2023-05-07)

[Full Changelog](https://github.com/Onemind-Services-LLC/netbox-secrets/compare/v1.7.6...v1.8.0)

**Closed issues:**

- \[Bug\]: Dont work after update netbox to 3.5.0 [\#53](https://github.com/Onemind-Services-LLC/netbox-secrets/issues/53)
- \[Bug\]: Unable to search secrets by name or assigned device \(UI  and API\) [\#49](https://github.com/Onemind-Services-LLC/netbox-secrets/issues/49)
- \[Bug\]: Unable to generate session key via API [\#47](https://github.com/Onemind-Services-LLC/netbox-secrets/issues/47)
- \[Bug\]: Migration \(from netbox-secretstore\) fails [\#44](https://github.com/Onemind-Services-LLC/netbox-secrets/issues/44)

**Merged pull requests:**

- PRVB [\#57](https://github.com/Onemind-Services-LLC/netbox-secrets/pull/57) ([abhi1693](https://github.com/abhi1693))
- Adds support for NetBox v3.5 [\#54](https://github.com/Onemind-Services-LLC/netbox-secrets/pull/54) ([kprince28](https://github.com/kprince28))
- Fix secret filters [\#51](https://github.com/Onemind-Services-LLC/netbox-secrets/pull/51) ([kprince28](https://github.com/kprince28))
- Add FormParser for session key view [\#50](https://github.com/Onemind-Services-LLC/netbox-secrets/pull/50) ([kirk444](https://github.com/kirk444))

## [v1.7.6](https://github.com/Onemind-Services-LLC/netbox-secrets/tree/v1.7.6) (2023-04-12)

[Full Changelog](https://github.com/Onemind-Services-LLC/netbox-secrets/compare/v1.7.5...v1.7.6)

**Closed issues:**

- \[Bug\]: secret on a other plugin object [\#45](https://github.com/Onemind-Services-LLC/netbox-secrets/issues/45)
- \[Feature\]: Add more filters for secrets table [\#39](https://github.com/Onemind-Services-LLC/netbox-secrets/issues/39)
- \[Feature\]: Do not allow to replace public key if only 1 user key exists in DB [\#38](https://github.com/Onemind-Services-LLC/netbox-secrets/issues/38)

**Merged pull requests:**

- Added migrations for object changes from old app [\#46](https://github.com/Onemind-Services-LLC/netbox-secrets/pull/46) ([abhi1693](https://github.com/abhi1693))

## [v1.7.5](https://github.com/Onemind-Services-LLC/netbox-secrets/tree/v1.7.5) (2023-01-31)

[Full Changelog](https://github.com/Onemind-Services-LLC/netbox-secrets/compare/v1.7.4...v1.7.5)

**Closed issues:**

- \[Bug\]: Unable to delete session key [\#34](https://github.com/Onemind-Services-LLC/netbox-secrets/issues/34)

**Merged pull requests:**

- PRVB [\#36](https://github.com/Onemind-Services-LLC/netbox-secrets/pull/36) ([abhi1693](https://github.com/abhi1693))
- Fixed session key delete [\#35](https://github.com/Onemind-Services-LLC/netbox-secrets/pull/35) ([abhi1693](https://github.com/abhi1693))

## [v1.7.4](https://github.com/Onemind-Services-LLC/netbox-secrets/tree/v1.7.4) (2023-01-30)

[Full Changelog](https://github.com/Onemind-Services-LLC/netbox-secrets/compare/v1.7.3...v1.7.4)

**Closed issues:**

- \[Housekeeping\]: Improve user key UI [\#27](https://github.com/Onemind-Services-LLC/netbox-secrets/issues/27)
- \[Docs\]: Add section of why this plugin was created and what is it trying to solve [\#25](https://github.com/Onemind-Services-LLC/netbox-secrets/issues/25)
- \[Bug\]: Secret role secrets count is always 0 [\#24](https://github.com/Onemind-Services-LLC/netbox-secrets/issues/24)

**Merged pull requests:**

- PRVB [\#31](https://github.com/Onemind-Services-LLC/netbox-secrets/pull/31) ([abhi1693](https://github.com/abhi1693))
- Added overview and features section to README.md [\#30](https://github.com/Onemind-Services-LLC/netbox-secrets/pull/30) ([abhi1693](https://github.com/abhi1693))
- Refactored code [\#29](https://github.com/Onemind-Services-LLC/netbox-secrets/pull/29) ([abhi1693](https://github.com/abhi1693))
- Improved user key UI [\#28](https://github.com/Onemind-Services-LLC/netbox-secrets/pull/28) ([abhi1693](https://github.com/abhi1693))

## [v1.7.3](https://github.com/Onemind-Services-LLC/netbox-secrets/tree/v1.7.3) (2023-01-23)

[Full Changelog](https://github.com/Onemind-Services-LLC/netbox-secrets/compare/v1.7.2...v1.7.3)

**Merged pull requests:**

- Prepare for Pypi [\#23](https://github.com/Onemind-Services-LLC/netbox-secrets/pull/23) ([abhi1693](https://github.com/abhi1693))

## [v1.7.2](https://github.com/Onemind-Services-LLC/netbox-secrets/tree/v1.7.2) (2023-01-19)

[Full Changelog](https://github.com/Onemind-Services-LLC/netbox-secrets/compare/v1.7.1...v1.7.2)

**Closed issues:**

- \[Feature\]: Add contact filterset [\#20](https://github.com/Onemind-Services-LLC/netbox-secrets/issues/20)

**Merged pull requests:**

- Removed SecretFilterSetMixin [\#22](https://github.com/Onemind-Services-LLC/netbox-secrets/pull/22) ([abhi1693](https://github.com/abhi1693))

## [v1.7.1](https://github.com/Onemind-Services-LLC/netbox-secrets/tree/v1.7.1) (2023-01-19)

[Full Changelog](https://github.com/Onemind-Services-LLC/netbox-secrets/compare/v1.7.0...v1.7.1)

**Merged pull requests:**

- Added contact filterset [\#21](https://github.com/Onemind-Services-LLC/netbox-secrets/pull/21) ([abhi1693](https://github.com/abhi1693))

## [v1.7.0](https://github.com/Onemind-Services-LLC/netbox-secrets/tree/v1.7.0) (2023-01-13)

[Full Changelog](https://github.com/Onemind-Services-LLC/netbox-secrets/compare/v1.6.0...v1.7.0)

**Merged pull requests:**

- Fixed autocomplete and uncaught form errors [\#19](https://github.com/Onemind-Services-LLC/netbox-secrets/pull/19) ([abhi1693](https://github.com/abhi1693))
- Updated documentation and fixed invalid session key [\#18](https://github.com/Onemind-Services-LLC/netbox-secrets/pull/18) ([abhi1693](https://github.com/abhi1693))
- Added generic relation for contacts [\#17](https://github.com/Onemind-Services-LLC/netbox-secrets/pull/17) ([abhi1693](https://github.com/abhi1693))

## [v1.6.0](https://github.com/Onemind-Services-LLC/netbox-secrets/tree/v1.6.0) (2023-01-08)

[Full Changelog](https://github.com/Onemind-Services-LLC/netbox-secrets/compare/v1.5.0...v1.6.0)

**Merged pull requests:**

- PRVB [\#15](https://github.com/Onemind-Services-LLC/netbox-secrets/pull/15) ([abhi1693](https://github.com/abhi1693))
- Changes to the workflow [\#14](https://github.com/Onemind-Services-LLC/netbox-secrets/pull/14) ([abhi1693](https://github.com/abhi1693))
- Added support for NetBox v3.4 [\#13](https://github.com/Onemind-Services-LLC/netbox-secrets/pull/13) ([abhi1693](https://github.com/abhi1693))

## [v1.5.0](https://github.com/Onemind-Services-LLC/netbox-secrets/tree/v1.5.0) (2023-01-08)

[Full Changelog](https://github.com/Onemind-Services-LLC/netbox-secrets/compare/v1.4.0...v1.5.0)

**Closed issues:**

- Housekeeping tasks [\#3](https://github.com/Onemind-Services-LLC/netbox-secrets/issues/3)

**Merged pull requests:**

- PRVB [\#12](https://github.com/Onemind-Services-LLC/netbox-secrets/pull/12) ([abhi1693](https://github.com/abhi1693))
- Added model extension to other apps [\#11](https://github.com/Onemind-Services-LLC/netbox-secrets/pull/11) ([abhi1693](https://github.com/abhi1693))

## [v1.4.0](https://github.com/Onemind-Services-LLC/netbox-secrets/tree/v1.4.0) (2022-12-30)

[Full Changelog](https://github.com/Onemind-Services-LLC/netbox-secrets/compare/69f98839760e72ea8372f6eb688f584840eedcc4...v1.4.0)

**Closed issues:**

- Recheck tests [\#2](https://github.com/Onemind-Services-LLC/netbox-secrets/issues/2)

**Merged pull requests:**

- Prepare for v1.4.0 [\#9](https://github.com/Onemind-Services-LLC/netbox-secrets/pull/9) ([abhi1693](https://github.com/abhi1693))
- Added workflows [\#8](https://github.com/Onemind-Services-LLC/netbox-secrets/pull/8) ([abhi1693](https://github.com/abhi1693))
- Added prerequisite models [\#7](https://github.com/Onemind-Services-LLC/netbox-secrets/pull/7) ([kprince28](https://github.com/kprince28))
- Bump minimatch from 3.0.4 to 3.1.2 in /netbox\_secrets/project-static [\#6](https://github.com/Onemind-Services-LLC/netbox-secrets/pull/6) ([dependabot[bot]](https://github.com/apps/dependabot))
- Bump json5 from 2.2.0 to 2.2.2 in /netbox\_secrets/project-static [\#5](https://github.com/Onemind-Services-LLC/netbox-secrets/pull/5) ([dependabot[bot]](https://github.com/apps/dependabot))
- Updated test cases [\#4](https://github.com/Onemind-Services-LLC/netbox-secrets/pull/4) ([kprince28](https://github.com/kprince28))
- Updated to be compatible with NetBox v3.3 [\#1](https://github.com/Onemind-Services-LLC/netbox-secrets/pull/1) ([kprince28](https://github.com/kprince28))



\* *This Changelog was automatically generated by [github_changelog_generator](https://github.com/github-changelog-generator/github-changelog-generator)*
