> [!IMPORTANT]
>
> 26.04 FREEZE March 11th: Non-bugfix PRs not ready by this date will wait for 26.06.
>
> RC1 is scheduled on _March 23rd_
>
> The final release is scheduled for April 15th.


## Checklist
Before submitting the PR, ensure the following tasks are completed. If an item is not applicable to your PR, please mark it as checked:

- [ ] The changelog has been updated in the relevant commit(s) according to the [guidelines](https://docs.corelightning.org/docs/coding-style-guidelines#changelog-entries-in-commit-messages).
- [ ] Tests have been added or modified to reflect the changes.
- [ ] Documentation has been reviewed and updated as needed.
- [ ] Related issues have been listed and linked, including any that this PR closes.
- [ ] *Important* All PRs must consider how to reverse any persistent changes for `tools/lightning-downgrade`
