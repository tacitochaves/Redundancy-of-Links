package Route;

use strict;
use warnings;

use Exporter qw(import);

our @EXPORT_OK = qw(ip_rule_list rule_add rule_del rule_emb ping_emb r_add_147 r_add_34);

sub ip_rule_list {
    my @ips;
    my $index;
    open( RULE, "ip rule list |" ) or die "Error rule!\n";
    my @lines = (<RULE>);
    close(RULE);
    
    foreach ( @lines ) {
        if ( /(172|192)\.(\d{1,3}\.){2}\d{1,3}/ and /LINK/ ) {            
            $index = index($_, "from");
            unshift(@ips, substr($_, $index));                 
        }                           
    }
    return @ips;
}

sub rule_add {
    my @r = @_;
    open( RULE, "ip rule add @r |" ) or die "Error Rule!\n";
    my @lines = (<RULE>);
    close(RULE);
}

sub rule_del {
    my @r = @_;
    open( RULE, "ip rule del @r |" ) or die "Error Rule!\n";
    my @lines = (<RULE>);
    close(RULE);
}

sub rule_emb {
    my $option = shift;
    my $dst    = shift;
    my $table  = shift;
    open( RULE, "ip rule " . $option . " to " . $dst . " lookup " . $table . "|" ) or die "PING Error!\n";
    my $iof = <RULE>;
    close(RULE);
    return 1;
}

sub ping_emb {
    my $dst   = shift;
    my $loss  = ();
    open( PING, "ping -c3 $dst |" ) or die "PING Error!\n";
    my @line = (<PING>);
    close(PING);
    foreach my $l (@line) {
        if ( $l =~ m/(\d+)%/ ) {
            $loss = "$1";
        }
    }
    return $loss;
}

sub r_add_147 {
    my @add;
    my $inf = shift;
    open( BUILDER, "<", "$inf" ) or die "Error: FwBuilder can not open the file\n";
    my @fw = (<BUILDER>);
    close( BUILDER );

    for ( @fw ) {
        if ( $_ =~ /1[790]\d?/ and /add/ and /LINK2$/ ) {
            if ( /\/sbin\/ip ru(le)? add/ ) {
                s/\/sbin\/ip ru(le)? add //g;
                unshift (@add, $_);
            }
        }
    }
    return @add;
}

sub r_add_34 {
    my @add;
    my $inf = shift;
    open( BUILDER, "<", "$inf" ) or die "Error: FwBuilder can not open the file\n";
    my @fw = (<BUILDER>);
    close( BUILDER );

    for ( @fw ) {
        if ( $_ =~ /1[790]\d?/ and /add/ and /LINK3$/ ) {
            if ( /\/sbin\/ip ru(le)? add/ ) {
                s/\/sbin\/ip ru(le)? add //g;
                unshift (@add, $_);
            }
        }
    }
    return @add;
}

1;
