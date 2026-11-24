# macOS system Perl. Called only after successful guest exit and confirmed cleanup.
use strict;
use warnings;
use Digest::SHA qw(sha256_hex);
use File::Temp;

my ($frame, $destination) = @ARGV;
open my $in, '<:raw', $frame or die "Cannot open observed result: $!\n";
my $n = read($in, my $bytes, 12);
defined($n) && $n == 11 && eof($in)
    && sha256_hex($bytes) eq '9f827af5202050f264dfa05aeec4603d0fcec968de43ed7b039ce6a2d6231b08'
    or die "Incomplete or unexpected observed result; nothing exported\n";
close $in or die "Cannot close observation: $!\n";

# Same-filesystem staging + link(2) publishes complete bytes or nothing.
# Unlike a check followed by rename, even a racing dangling symlink wins.
my $stage = File::Temp->new(DIR => '.', TEMPLATE => '.aragorn-result-XXXXXXXX', UNLINK => 1);
binmode $stage;
print {$stage} $bytes or die "Cannot stage result: $!\n";
close $stage or die "Cannot close staged result: $!\n";
link($stage->filename, $destination) or die "Cannot create new output (never overwritten): $!\n";
