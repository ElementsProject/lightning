.NH 1
a \c
.pdfhref W -D https://foo.com -- https://foo.com
now\c
.pdfhref W -A "\c" -D https://bar.com -- world
bc
.pdfhref O 1 a https://foo.com nowworldbc
.pdfhref M a-httpsfoo.com-nowworldbc
.LP
c
