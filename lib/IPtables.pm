package IPtables;

use strict;
use warnings;

use Exporter qw(import);

our @EXPORT_OK = qw( iptables_save ipt_forward ipt_nat add_ipt );

sub iptables_save {
    my @ips = shift;
    my @save;
    open(IPTABLES, "iptables-save | grep @ips |") or die "IPTables Error\n";
    my @iptables = <IPTABLES>;
    close(IPTABLES);

    foreach ( @iptables ) {
        if ( /FORWARD|PREROUTING/ ) {
            s/-A //;
            unshift(@save, $_);
        }
    }
    return @save;
}

sub ipt_forward {
    my $opt = shift;
    my @forward = shift;
    open( FORWARD, "iptables $opt @forward |" ) or die "Error to delete Forward\n";
    close(FORWARD);
}

sub ipt_nat {
    my $opt = shift;
    my @nat = shift;
    open( PREROUTING, "iptables -t nat $opt  @nat |" ) or die "Error to delete Forward\n";
    close(PREROUTING);
}

sub add_ipt {
    my $file = shift;
    my @ips  = shift;
    my @to_iptables;
    open( FILE, "<", $file ) or die "Error: Can'not open this file: $file\n";
    my @builder = <FILE>;
    close(FILE);
    
    foreach my $fw ( @builder ) {
        unshift(@to_iptables, $fw);
    }
    return @to_iptables;
}

1;
