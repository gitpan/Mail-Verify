package Mail::Verify;

use Net::DNS;
use IO::Socket;
require Exporter;
use strict;
use vars qw(@ISA @EXPORT_OK $BAD $VERSION);
@ISA = qw(Exporter);
@EXPORT_OK = qw(isfake $BAD);

$VERSION = '0.00';

$BAD = "SMTP response not understood";

sub isfake ($;$) {
	my @tokens = split(/\@/, shift);
	my $mx = shift;
	unless ($mx) {
		return 'not in user@host format' unless @tokens == 2;
		foreach (@tokens) {
			return 'contains illegal characters' if /[;()<>]/;
		}
		return 'malformed mail domain' unless ($tokens[1] =~ /\./);
		my @mx = mx($tokens[1]);
		return 'bogus mail domain' unless @mx;
		@mx = sort { $b->preference <=> $a->preference} @mx;
		$mx = $mx[0]->exchange;
	}
	my $sock = new IO::Socket::INET("$mx:25") || return undef;
	my $result = step1($sock);
	close($sock);
	$result;
}

sub step1 {
	my $sock = shift;
	return $BAD unless code($sock) == 220;
	print $sock "HELO Mail-Check\r\n";
	return $BAD unless code($sock) == 250;
	print $sock "EXPN $tokens[0]\@$tokens[1]\r\n";
	my $code = code($sock);
	return step2($sock) if ($code == 502);
	return "" if ($code == 250);
	return "bogus username" if ($code == 550);
	return $BAD;
}

sub step2 {
	my $sock = shift;
	print $sock "VRFY $tokens[0]\@$tokens[1]\r\n";
	return step3($sock) if ($code == 252);
	return "bogus username" if ($code == 550);
	return "" if ($code == 250);
	return $BAD;
}

sub step3 {
	my $sock = shift;
	print $sock "MAIL FROM:<>\r\n";
	return $BAD unless code($sock) == 250;
	print $sock "RCPT TO:<$tokens[0]\@$tokens[1]>\r\n";
	return "bogus username" if ($code == 550);
	return "" if ($code == 250);
	return $BAD;
}

sub code ($) {
	my $sock = shift;
	my $line = <$sock>;
	my @tokens = split(/\s+/, $line);
	$tokens[0];
}

1;
__END__

=head1 NAME

Mail::Verify - Perl extension for validation of email addresses

=head1 SYNOPSIS

  use Mail::Verify qw(isfake);

  $reason = isfake('bill@microsoft.com');
  if ($reason) {
    print "Bad email: $reason\n";
  } elsif (defined($reason)) {
    print "Email address perfect\n";
  } else {
    print "Could not verify email address: EXPN is turned off at target computer";
  }

  $reason = isfake('bigboss', 'mail.acme.com');
  ...

=head1 DESCRIPTION

This module checks validity of email addresses. It ensure the
existence of a username and domain, unless you specified the
MTA, searches the DNS for the MTA (if not specified), and then
attempts to use the SMTP keyword EXPN to verify the username.
Since EXPN is usually turned off, the module will return I<undef>
in such cases, and defined but false if the verification passed.
If for any reason the check failed, the module will return a string
describing the reason.

=head1 CAVEATS

Contemporary ISPs never turn EXPN on, to prevent mail abusers
harass more efficiently by molesting only existing addresses
with junk mail. Therefore, this is not an excellent solution
to check the fill-out forms in your site for users supplying
false email addresses. Most addresses associated with valid MTAs
will return I<undef>.

=head1 AUTHOR

Ariel Brosh, schop@cpan.org.

=head1 SEE ALSO

perl(1).

=cut
