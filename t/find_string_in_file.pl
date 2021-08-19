
use strict;
use FileHandle;

# arg0 = filename; arg1 = start position; arg2 = string to find
sub find_string_in_file {
    my $file_end_size = -s $_[0] or die "(find_string_in_file.pl) Failed to access file: " . $_[0];
    my $bytes_to_read = $file_end_size - $_[1];

    my $file_content;
    open FILE, $_[0] || die $!;
    seek(FILE, $_[1], IO::Seekable::SEEK_SET);
    my $bytes_read = read(FILE, $file_content, $bytes_to_read);

    #    if (index($file_content, $_[2]) != -1) {
    if ($file_content =~ $_[2]) {
        return 1;
    }
    return 0;
}
1;

