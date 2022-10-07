.NH 1
a \c
.pdfhref W -D https://foo.com -- https://foo.com
now \c
.pdfhref W -D https://bar.com -- world
b
.pdfhref O 1 a https://foo.com now world b
.pdfhref M a-httpsfoo.com-now-world-b
.LP
c
