.PHONY: regress
.SUFFIXES: .xml .md .html .pdf .1 .1.html .3 .3.html .5 .5.html .thumb.jpg .png .in.pc .pc .valgrind .old.md .diff-valgrind

include Makefile.configure

VERSION		 = 1.0.0
LIBVER		 = 1
OBJS		 = autolink.o \
		   buffer.o \
		   diff.o \
		   document.o \
		   entity.o \
		   gemini.o \
		   html.o \
		   html_escape.o \
		   latex.o \
		   library.o \
		   libdiff.o \
		   nroff.o \
		   odt.o \
		   smartypants.o \
		   term.o \
		   tree.o \
		   util.o
COMPAT_OBJS	 = compats.o
WWWDIR		 = /var/www/vhosts/kristaps.bsd.lv/htdocs/lowdown
HTMLS		 = archive.html \
		   atom.xml \
		   diff.html \
		   diff.diff.html \
		   index.html \
		   README.html \
		   $(MANS)
MANS		 = $(MAN1S) $(MAN3S) $(MAN5S)
MAN1S		 = man/lowdown.1.html \
		   man/lowdown-diff.1.html
MAN5S =  	   man/lowdown.5.html
MAN3S = 	   man/lowdown.3.html \
		   man/lowdown_buf.3.html \
		   man/lowdown_buf_diff.3.html \
		   man/lowdown_buf_free.3.html \
		   man/lowdown_buf_new.3.html \
		   man/lowdown_diff.3.html \
		   man/lowdown_doc_free.3.html \
		   man/lowdown_doc_new.3.html \
		   man/lowdown_doc_parse.3.html \
		   man/lowdown_file.3.html \
		   man/lowdown_file_diff.3.html \
		   man/lowdown_gemini_free.3.html \
		   man/lowdown_gemini_new.3.html \
		   man/lowdown_gemini_rndr.3.html \
		   man/lowdown_html_free.3.html \
		   man/lowdown_html_new.3.html \
		   man/lowdown_html_rndr.3.html \
		   man/lowdown_latex_free.3.html \
		   man/lowdown_latex_new.3.html \
		   man/lowdown_latex_rndr.3.html \
		   man/lowdown_metaq_free.3.html \
		   man/lowdown_node_free.3.html \
		   man/lowdown_nroff_free.3.html \
		   man/lowdown_nroff_new.3.html \
		   man/lowdown_nroff_rndr.3.html \
		   man/lowdown_odt_free.3.html \
		   man/lowdown_odt_new.3.html \
		   man/lowdown_odt_rndr.3.html \
		   man/lowdown_term_free.3.html \
		   man/lowdown_term_new.3.html \
		   man/lowdown_term_rndr.3.html \
		   man/lowdown_tree_rndr.3.html
SOURCES		 = autolink.c \
		   buffer.c \
		   compats.c \
		   diff.c \
		   document.c \
		   entity.c \
		   gemini.c \
		   html.c \
		   html_escape.c \
		   latex.c \
		   libdiff.c \
		   library.c \
		   main.c \
		   nroff.c \
		   odt.c \
		   smartypants.c \
		   term.c \
		   tests.c \
		   tree.c \
		   util.c
HEADERS 	 = extern.h \
		   libdiff.h \
		   lowdown.h \
		   term.h
PDFS		 = diff.pdf \
		   diff.diff.pdf \
		   index.latex.pdf \
		   index.mandoc.pdf \
		   index.nroff.pdf
MDS		 = index.md README.md
CSSS		 = diff.css template.css
JSS		 = diff.js
IMAGES		 = screen-mandoc.png \
		   screen-groff.png \
		   screen-term.png
THUMBS		 = screen-mandoc.thumb.jpg \
		   screen-groff.thumb.jpg \
		   screen-term.thumb.jpg
VALGRINDS	!= for f in `find regress -name \*.md` ; do echo `dirname $$f`/`basename $$f .md`.valgrind ; done
VALGRINDDIFFS	!= for f in `find regress/diff -name \*.old.md` ; do echo `dirname $$f`/`basename $$f .old.md`.diff-valgrind ; done
CFLAGS		+= -fPIC

# Only for MarkdownTestv1.0.3 in regress/original.

REGRESS_ARGS	 = "--out-no-smarty"
REGRESS_ARGS	+= "--parse-no-img-ext"
REGRESS_ARGS	+= "--parse-no-metadata"
REGRESS_ARGS	+= "--html-no-head-ids"
REGRESS_ARGS	+= "--html-no-skiphtml"
REGRESS_ARGS	+= "--html-no-escapehtml"
REGRESS_ARGS	+= "--html-no-owasp"
REGRESS_ARGS	+= "--html-no-num-ent"
REGRESS_ARGS	+= "--parse-no-autolink"
REGRESS_ARGS	+= "--parse-no-cmark"
REGRESS_ARGS	+= "--parse-no-deflists"

VALGRIND_ARGS	 = -q --leak-check=full --leak-resolution=high --show-reachable=yes

all: bins lowdown.pc liblowdown.so
bins: lowdown lowdown-diff

valgrind: $(VALGRINDS) $(VALGRINDDIFFS)
	@for f in $(VALGRINDS) ; do \
		if [ -s $$f ]; then \
			echo `dirname $$f`/`basename $$f .valgrind`.md ; \
			cat $$f ; \
		fi ; \
	done
	@for f in $(VALGRINDDIFFS) ; do \
		if [ -s $$f ]; then \
			echo `dirname $$f`/`basename $$f .diff-valgrind`.old.md ; \
			cat $$f ; \
		fi ; \
	done

$(VALGRINDS) $(VALGRINDDIFFS): bins

.old.md.diff-valgrind:
	@rm -f $@
	valgrind $(VALGRIND_ARGS) ./lowdown-diff -s -tfodt $< `dirname $<`/`basename $< .old.md`.new.md >/dev/null 2>>$@
	valgrind $(VALGRIND_ARGS) ./lowdown-diff -s -thtml $< `dirname $<`/`basename $< .old.md`.new.md >/dev/null 2>>$@
	valgrind $(VALGRIND_ARGS) ./lowdown-diff -s -tms $< `dirname $<`/`basename $< .old.md`.new.md >/dev/null 2>>$@
	valgrind $(VALGRIND_ARGS) ./lowdown-diff -s -tman $< `dirname $<`/`basename $< .old.md`.new.md >/dev/null 2>>$@
	valgrind $(VALGRIND_ARGS) ./lowdown-diff -s -tterm $< `dirname $<`/`basename $< .old.md`.new.md >/dev/null 2>>$@
	valgrind $(VALGRIND_ARGS) ./lowdown-diff -s -tgemini $< `dirname $<`/`basename $< .old.md`.new.md >/dev/null 2>>$@

.md.valgrind:
	@rm -f $@
	valgrind $(VALGRIND_ARGS) ./lowdown -s -tfodt $< >/dev/null 2>>$@
	valgrind $(VALGRIND_ARGS) ./lowdown -s -thtml $< >/dev/null 2>>$@
	valgrind $(VALGRIND_ARGS) ./lowdown -s -tms $< >/dev/null 2>>$@
	valgrind $(VALGRIND_ARGS) ./lowdown -s -tman $< >/dev/null 2>>$@
	valgrind $(VALGRIND_ARGS) ./lowdown -s -tterm $< >/dev/null 2>>$@
	valgrind $(VALGRIND_ARGS) ./lowdown -s -tgemini $< >/dev/null 2>>$@
	valgrind $(VALGRIND_ARGS) ./lowdown -s -tlatex $< >/dev/null 2>>$@

www: all $(HTMLS) $(PDFS) $(THUMBS) lowdown.tar.gz lowdown.tar.gz.sha512

installwww: www
	mkdir -p $(WWWDIR)/snapshots
	$(INSTALL) -m 0444 $(THUMBS) $(IMAGES) $(MDS) $(HTMLS) $(CSSS) $(JSS) $(PDFS) $(WWWDIR)
	$(INSTALL) -m 0444 lowdown.tar.gz $(WWWDIR)/snapshots/lowdown-$(VERSION).tar.gz
	$(INSTALL) -m 0444 lowdown.tar.gz.sha512 $(WWWDIR)/snapshots/lowdown-$(VERSION).tar.gz.sha512
	$(INSTALL) -m 0444 lowdown.tar.gz $(WWWDIR)/snapshots
	$(INSTALL) -m 0444 lowdown.tar.gz.sha512 $(WWWDIR)/snapshots

lowdown: liblowdown.a main.o
	$(CC) -o $@ main.o liblowdown.a $(LDFLAGS) $(LDADD_MD5) -lm

lowdown-diff: lowdown
	ln -f lowdown lowdown-diff

liblowdown.a: $(OBJS) $(COMPAT_OBJS)
	$(AR) rs $@ $(OBJS) $(COMPAT_OBJS)

liblowdown.so: $(OBJS) $(COMPAT_OBJS)
	$(CC) -shared -o $@.$(LIBVER) $(OBJS) $(COMPAT_OBJS) $(LDFLAGS) $(LDADD_MD5) -Wl,-soname,$@.$(LIBVER)
	ln -sf $@.$(LIBVER) $@

install: bins
	mkdir -p $(DESTDIR)$(BINDIR)
	mkdir -p $(DESTDIR)$(MANDIR)/man1
	mkdir -p $(DESTDIR)$(MANDIR)/man5
	mkdir -p $(DESTDIR)$(SHAREDIR)/lowdown/odt
	$(INSTALL_DATA) share/odt/styles.xml $(DESTDIR)$(SHAREDIR)/lowdown/odt
	$(INSTALL_PROGRAM) lowdown $(DESTDIR)$(BINDIR)
	$(INSTALL_PROGRAM) lowdown-diff $(DESTDIR)$(BINDIR)
	for f in $(MAN1S) $(MAN5S) ; do \
		name=`basename $$f .html` ; \
		section=$${name##*.} ; \
		$(INSTALL_MAN) man/$$name $(DESTDIR)$(MANDIR)/man$$section ; \
	done

install_lib_common: lowdown.pc
	mkdir -p $(DESTDIR)$(MANDIR)/man3
	mkdir -p $(DESTDIR)$(LIBDIR)/pkgconfig
	mkdir -p $(DESTDIR)$(INCLUDEDIR)
	$(INSTALL_DATA) lowdown.pc $(DESTDIR)$(LIBDIR)/pkgconfig
	$(INSTALL_DATA) lowdown.h $(DESTDIR)$(INCLUDEDIR)
	for f in $(MAN3S) ; do \
		name=`basename $$f .html` ; \
		section=$${name##*.} ; \
		$(INSTALL_MAN) man/$$name $(DESTDIR)$(MANDIR)/man$$section ; \
	done

install_shared: liblowdown.so install_lib_common
	$(INSTALL_LIB) liblowdown.so.$(LIBVER) $(DESTDIR)$(LIBDIR)

install_static: liblowdown.a install_lib_common
	$(INSTALL_LIB) liblowdown.a $(DESTDIR)$(LIBDIR)

install_libs: install_shared install_static

distcheck: lowdown.tar.gz.sha512
	mandoc -Tlint -Werror man/*.[135]
	newest=`grep "<h1>" versions.xml | tail -1 | sed 's![ 	]*!!g'` ; \
	       [ "$$newest" = "<h1>$(VERSION)</h1>" ] || \
		{ echo "Version $(VERSION) not newest in versions.xml" 1>&2 ; exit 1 ; }
	[ "`openssl dgst -sha512 -hex lowdown.tar.gz`" = "`cat lowdown.tar.gz.sha512`" ] || \
		{ echo "Checksum does not match." 1>&2 ; exit 1 ; }
	rm -rf .distcheck
	mkdir -p .distcheck
	( cd .distcheck && tar -zvxpf ../lowdown.tar.gz )
	( cd .distcheck/lowdown-$(VERSION) && ./configure PREFIX=prefix )
	( cd .distcheck/lowdown-$(VERSION) && $(MAKE) )
	( cd .distcheck/lowdown-$(VERSION) && $(MAKE) regress )
	( cd .distcheck/lowdown-$(VERSION) && $(MAKE) install )
	rm -rf .distcheck

$(PDFS) index.xml README.xml: lowdown

index.html README.html: template.xml

.md.pdf:
	./lowdown --nroff-no-numbered -s -tms $< | \
		pdfroff -i -mspdf -t -k > $@

index.latex.pdf: index.md $(THUMBS)
	./lowdown -s -tlatex index.md >index.latex.latex
	pdflatex index.latex.latex
	pdflatex index.latex.latex

index.mandoc.pdf: index.md
	./lowdown --nroff-no-numbered -s -tman index.md | \
		mandoc -Tpdf > $@

index.nroff.pdf: index.md
	./lowdown --nroff-no-numbered -s -tms index.md | \
		pdfroff -i -mspdf -t -k > $@

.xml.html:
	sblg -t template.xml -s date -o $@ -C $< $< versions.xml

archive.html: archive.xml versions.xml
	sblg -t archive.xml -s date -o $@ versions.xml

atom.xml: atom-template.xml versions.xml
	sblg -a -t atom-template.xml -s date -o $@ versions.xml

diff.html: diff.md lowdown
	./lowdown -s diff.md >$@

diff.diff.html: diff.md diff.old.md lowdown-diff
	./lowdown-diff -s diff.old.md diff.md >$@

diff.diff.pdf: diff.md diff.old.md lowdown-diff
	./lowdown-diff --nroff-no-numbered -s -tms diff.old.md diff.md | \
		pdfroff -i -mspdf -t -k > $@

$(HTMLS): versions.xml lowdown

.md.xml:
	( echo "<?xml version=\"1.0\" encoding=\"UTF-8\" ?>" ; \
	  echo "<article data-sblg-article=\"1\">" ; \
	  ./lowdown $< ; \
	  echo "</article>" ; ) >$@

.1.1.html .3.3.html .5.5.html:
	mandoc -Thtml -Ostyle=https://bsd.lv/css/mandoc.css $< >$@

lowdown.tar.gz.sha512: lowdown.tar.gz
	openssl dgst -sha512 -hex lowdown.tar.gz >$@

lowdown.tar.gz:
	mkdir -p .dist/lowdown-$(VERSION)/
	mkdir -p .dist/lowdown-$(VERSION)/man
	mkdir -p .dist/lowdown-$(VERSION)/share/odt
	mkdir -p .dist/lowdown-$(VERSION)/regress/original
	mkdir -p .dist/lowdown-$(VERSION)/regress/standalone
	mkdir -p .dist/lowdown-$(VERSION)/regress/metadata
	mkdir -p .dist/lowdown-$(VERSION)/regress/diff
	$(INSTALL) -m 0644 $(HEADERS) .dist/lowdown-$(VERSION)
	$(INSTALL) -m 0644 $(SOURCES) .dist/lowdown-$(VERSION)
	$(INSTALL) -m 0644 share/odt/* .dist/lowdown-$(VERSION)/share/odt
	$(INSTALL) -m 0644 lowdown.in.pc Makefile LICENSE.md .dist/lowdown-$(VERSION)
	$(INSTALL) -m 0644 man/*.1 man/*.3 man/*.5 .dist/lowdown-$(VERSION)/man
	$(INSTALL) -m 0755 configure .dist/lowdown-$(VERSION)
	$(INSTALL) -m 644 regress/original/* .dist/lowdown-$(VERSION)/regress/original
	$(INSTALL) -m 644 regress/*.* .dist/lowdown-$(VERSION)/regress
	$(INSTALL) -m 644 regress/standalone/* .dist/lowdown-$(VERSION)/regress/standalone
	$(INSTALL) -m 644 regress/metadata/* .dist/lowdown-$(VERSION)/regress/metadata
	$(INSTALL) -m 644 regress/diff/* .dist/lowdown-$(VERSION)/regress/diff
	( cd .dist/ && tar zcf ../$@ lowdown-$(VERSION) )
	rm -rf .dist/

$(OBJS) $(COMPAT_OBJS) main.o: config.h

$(OBJS): extern.h lowdown.h

term.o: term.h

main.o: lowdown.h

clean:
	rm -f $(OBJS) $(COMPAT_OBJS) main.o
	rm -f lowdown lowdown-diff liblowdown.a liblowdown.so liblowdown.so.$(LIBVER) lowdown.pc
	rm -f index.xml diff.xml diff.diff.xml README.xml lowdown.tar.gz.sha512 lowdown.tar.gz
	rm -f $(PDFS) $(HTMLS) $(THUMBS) $(VALGRINDS) $(VALGRINDDIFFS)
	rm -f index.latex.aux index.latex.latex index.latex.log index.latex.out

distclean: clean
	rm -f Makefile.configure config.h config.log config.h.old config.log.old

regress: bins
	tmp1=`mktemp` ; \
	tmp2=`mktemp` ; \
	for f in regress/original/*.text ; do \
		echo "$$f" ; \
		want="`dirname \"$$f\"`/`basename \"$$f\" .text`.html" ; \
		sed -e '/^[ ]*$$/d' "$$want" > $$tmp1 ; \
		./lowdown $(REGRESS_ARGS) "$$f" | \
			sed -e 's!	! !g' | sed -e '/^[ ]*$$/d' > $$tmp2 ; \
		diff -uw $$tmp1 $$tmp2 ; \
		./lowdown -s -thtml "$$f" >/dev/null 2>&1 ; \
		./lowdown -s -tlatex "$$f" >/dev/null 2>&1 ; \
		./lowdown -s -tman "$$f" >/dev/null 2>&1 ; \
		./lowdown -s -tms "$$f" >/dev/null 2>&1 ; \
		./lowdown -s -tfodt "$$f" >/dev/null 2>&1 ; \
		./lowdown -s -tterm "$$f" >/dev/null 2>&1 ; \
		./lowdown -s -ttree "$$f" >/dev/null 2>&1 ; \
	done  ; \
	for f in regress/*.md ; do \
		echo "$$f" ; \
		if [ -f regress/`basename $$f .md`.html ]; then \
			./lowdown -thtml $$f >$$tmp1 2>&1 ; \
			diff -uw regress/`basename $$f .md`.html $$tmp1 ; \
		fi ; \
		if [ -f regress/`basename $$f .md`.fodt ]; then \
			./lowdown -tfodt $$f >$$tmp1 2>&1 ; \
			diff -uw regress/`basename $$f .md`.fodt $$tmp1 ; \
		fi ; \
		if [ -f regress/`basename $$f .md`.term ]; then \
			./lowdown -tterm $$f >$$tmp1 2>&1 ; \
			diff -uw regress/`basename $$f .md`.term $$tmp1 ; \
		fi ; \
		if [ -f regress/`basename $$f .md`.latex ]; then \
			./lowdown -tlatex $$f >$$tmp1 2>&1 ; \
			diff -uw regress/`basename $$f .md`.latex $$tmp1 ; \
		fi ; \
		if [ -f regress/`basename $$f .md`.ms ]; then \
			./lowdown -tms $$f >$$tmp1 2>&1 ; \
			diff -uw regress/`basename $$f .md`.ms $$tmp1 ; \
		fi ; \
		if [ -f regress/`basename $$f .md`.man ]; then \
			./lowdown -tman $$f >$$tmp1 2>&1 ; \
			diff -uw regress/`basename $$f .md`.man $$tmp1 ; \
		fi ; \
		if [ -f regress/`basename $$f .md`.gemini ]; then \
			./lowdown -tgemini $$f >$$tmp1 2>&1 ; \
			diff -uw regress/`basename $$f .md`.gemini $$tmp1 ; \
		fi ; \
	done ; \
	for f in regress/standalone/*.md ; do \
		echo "$$f" ; \
		if [ -f regress/standalone/`basename $$f .md`.html ]; then \
			./lowdown -s -thtml $$f >$$tmp1 2>&1 ; \
			diff -uw regress/standalone/`basename $$f .md`.html $$tmp1 ; \
		fi ; \
		if [ -f regress/standalone/`basename $$f .md`.fodt ]; then \
			./lowdown -s -tfodt $$f >$$tmp1 2>&1 ; \
			diff -uw regress/standalone/`basename $$f .md`.fodt $$tmp1 ; \
		fi ; \
		if [ -f regress/standalone/`basename $$f .md`.latex ]; then \
			./lowdown -s -tlatex $$f >$$tmp1 2>&1 ; \
			diff -uw regress/standalone/`basename $$f .md`.latex $$tmp1 ; \
		fi ; \
		if [ -f regress/standalone/`basename $$f .md`.ms ]; then \
			./lowdown -s -tms $$f >$$tmp1 2>&1 ; \
			diff -uw regress/standalone/`basename $$f .md`.ms $$tmp1 ; \
		fi ; \
		if [ -f regress/standalone/`basename $$f .md`.man ]; then \
			./lowdown -s -tman $$f >$$tmp1 2>&1 ; \
			diff -uw regress/standalone/`basename $$f .md`.man $$tmp1 ; \
		fi ; \
		if [ -f regress/standalone/`basename $$f .md`.gemini ]; then \
			./lowdown -s -tgemini $$f >$$tmp1 2>&1 ; \
			diff -uw regress/standalone/`basename $$f .md`.gemini $$tmp1 ; \
		fi ; \
	done ; \
	for f in regress/metadata/*.md ; do \
		echo "$$f" ; \
		if [ -f regress/metadata/`basename $$f .md`.txt ]; then \
			./lowdown -X test $$f >$$tmp1 2>&1 ; \
			diff -uw regress/metadata/`basename $$f .md`.txt $$tmp1 ; \
		fi ; \
	done ; \
	for f in regress/diff/*.old.md ; do \
		bf=`dirname $$f`/`basename $$f .old.md` ; \
		echo "$$f -> $$bf.new.md" ; \
		if [ -f $$bf.html ]; then \
			./lowdown-diff -s -thtml $$f $$bf.new.md >$$tmp1 2>&1 ; \
			diff -uw $$bf.html $$tmp1 ; \
		fi ; \
		if [ -f $$bf.ms ]; then \
			./lowdown-diff -s -tms $$f $$bf.new.md >$$tmp1 2>&1 ; \
			diff -uw $$bf.ms $$tmp1 ; \
		fi ; \
		if [ -f $$bf.man ]; then \
			./lowdown-diff -s -tman $$f $$bf.new.md >$$tmp1 2>&1 ; \
			diff -uw $$bf.man $$tmp1 ; \
		fi ; \
		if [ -f $$bf.latex ]; then \
			./lowdown-diff -s -tlatex $$f $$bf.new.md >$$tmp1 2>&1 ; \
			diff -uw $$bf.latex $$tmp1 ; \
		fi ; \
	done ; \
	rm -f $$tmp1 ; \
	rm -f $$tmp2

.png.thumb.jpg:
	convert $< -thumbnail 350 -quality 50 $@

.in.pc.pc:
	sed -e "s!@PREFIX@!$(PREFIX)!g" \
	    -e "s!@LIBDIR@!$(LIBDIR)!g" \
	    -e "s!@INCLUDEDIR@!$(INCLUDEDIR)!g" \
	    -e "s!@VERSION@!$(VERSION)!g" $< >$@
