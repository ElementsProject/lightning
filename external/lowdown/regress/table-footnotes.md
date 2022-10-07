
This used to crash -Tterm because the footnote size was saved and zeroed
prior to table column-width scanning, then restored.  However, this
could result in off-by-ones or -twos because the actual footnotes may
have gone double-digit while the zeroed wouldn't.

a[^1]
a[^2]
a[^3]
a[^4]
a[^5]
a[^6]
a[^7]
a[^8]

| Officer         | Rank                 |
| --------------: | -------------------- |
| Jean-Luc Picard | Captain              |
| Worf[^9]            | Lieutenant Commander |
| Data[^10]           | Lieutenant Commander |
| William Riker[^11]   | Commander            |

[^1]: foo
[^2]: foo
[^3]: foo
[^4]: foo
[^5]: foo
[^6]: foo
[^7]: foo
[^8]: foo
[^9]: foo
[^10]: foo
[^11]: foo
