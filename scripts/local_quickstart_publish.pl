# macOS system Perl. Called only after successful guest exit and confirmed cleanup.
use strict;
use warnings;
use File::Temp;

@ARGV == 4 or die "Missing local verification inputs\n";
my ($frame, $destination, $a, $b) = @ARGV;
for ($a, $b) {
    /\A-?(?:0|[1-9][0-9]{0,9})\z/ && $_ >= -2147483648 && $_ <= 2147483647
        or die "Invalid local operand\n";
}
# The guest supplies only observed bytes, never the expected answer or digest.
my $expected = '{"total":' . ($a + $b) . '}';
open my $in, '<:raw', $frame or die "Cannot open observed result: $!\n";
my $n = read($in, my $bytes, length($expected) + 1);
defined($n) && $bytes eq $expected && eof($in)
    or die "Incomplete or unexpected observed result; nothing exported\n";
close $in or die "Cannot close observation: $!\n";

# Same-filesystem staging + link(2) publishes complete bytes or nothing.
# Unlike a check followed by rename, even a racing dangling symlink wins.
my $stage = File::Temp->new(DIR => '.', TEMPLATE => '.aragorn-result-XXXXXXXX', UNLINK => 1);
binmode $stage;
print {$stage} $bytes or die "Cannot stage result: $!\n";
close $stage or die "Cannot close staged result: $!\n";
link($stage->filename, $destination) or die "Cannot create new output (never overwritten): $!\n";
