## $Id: Makefile.am,v 1.70 2004/06/24 15:08:37 jhewlett Exp $
AUTOMAKE_OPTIONS=foreign no-dependencies
SUBDIRS = src doc etc rules templates contrib

INCLUDES = @INCLUDES@

EXTRA_DIST = ChangeLog snort.8 LICENSE verstuff.pl RELEASE.NOTES

man_MANS = snort.8

DISTCLEANFILES=stamp-h.in


dist-hook:
# always ensure that the win32 build is in sync
	perl $(distdir)/verstuff.pl $(distdir)
# work around a horrible doc/Makefile.am
	rm -rf $(distdir)/doc/signatures/CVS
