use ExtUtils::MakeMaker;
# See lib/ExtUtils/MakeMaker.pm for details of how to influence
# the contents of the Makefile that is written.

sub MY::postamble {
        package MY;
        shift->SUPER::postamble . <<'MAKE';
distdir : README

README : Verify.pm
	@$(PERL) -MPod::Text -e "pod2text('$<');" > $@

MAKE
}

WriteMakefile(
    'NAME'	=> 'Mail::Verify',
    'VERSION_FROM' => 'Verify.pm', # finds $VERSION
    'dist' => {'COMPRESS' => 'gzip --best --force'},
);
