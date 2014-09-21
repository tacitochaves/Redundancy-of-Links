package SCHEMA::DataBase;

use strict;
use warnings;
use DBI;

sub connect {
    my $conf = {
        database =>
          "dbi:mysql:dbname=Redundancy_Teste;host=192.168.0.201:3306",
        username => "chaves",
        password => "************",

    };
    return DBI->connect( $conf->{database}, $conf->{username},
        $conf->{password} );
}

1;
