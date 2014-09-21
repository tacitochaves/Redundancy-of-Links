#!/usr/bin/env perl
#
# This program will make the redundancy between two internet links.
#
# Author: Tácito Chaves - 2014-06-25
# e-mail: chaves@tchaves.com.br
# skype: tacito.chaves

# informação de links:  
# EMB  = LINK2
# EMB2 = LINK3

use strict;
use warnings;

use FindBin;
use lib "$FindBin::Bin/lib";

use Route qw( ip_rule_list rule_add rule_del rule_emb ping_emb r_add_147 r_add_34 );
use IPtables qw( iptables_save ipt_forward ipt_nat add_ipt );
use SCHEMA::DataBase;

use Time::Piece;
use Net::SMTP::TLS;
use POSIX qw(strftime);
use File::Copy qw(copy);


use constant {
    GW_OI         => '10.0.4.2',
    GW_EMB34      => '10.0.3.2',
    GW_EMB147     => '10.0.5.2',
    INT_OI        => 'eth3',
    INT_EMB34     => 'eth4',
    INT_EMB147    => 'eth5',
    DESTINO       => '8.8.8.8',
    DESTINO2      => '8.8.4.4',
    LOG           => '/tmp/log_info',
    SQUID         => "/etc/squid/squid.conf",
    BKP           => "/etc/squid/backup",
};

my %msg = (
    OI_UP         => "LINK DA OI - UP",
    OI_DOWN       => "LINK DA OI - DOWN",
    EMB34_UP      => "LINK DA EMBRATEL 62.34 - UP",
    EMB34_DOWN    => "LINK DA EMBRATEL 62.34 - DOWN",
    EMB147_UP     => "LINK DA EMBRATEL 254.147 - UP",
    EMB147_DOWN   => "LINK DA EMBRATEL 254.147 - DOWN",
    LINK_DOWN     => "LINK DA OI E OI E EMBRATEL 62.34 - DOWN",
);

my %options = (
    fwbuilder => "/etc/fw/fw1sesma.fw",
    destino    => "8.8.4.4", 
    arquivo   => "/etc/fw/regras_firewall.txt",
);

# declaration of variables
my $date          = get_date();
my $packet_loss;
my $gateway       = get_default();
my $interface     = get_int();
my $dbh           = SCHEMA::DataBase->connect;

#check if the default link is up
if ( $gateway eq GW_OI && $interface eq INT_OI ) {
    $packet_loss = get_ping(INT_OI);
    if ( $packet_loss eq "100" ) {
        $dbh->do("UPDATE Current SET id_status = 2 WHERE id_link = 3");
        route_add(GW_EMB34);
        route_del(GW_OI);
        comment_squid_oi();
        $packet_loss = get_ping(INT_EMB34);

        # checks if the secondary link is up before putting the default route
        if ( $packet_loss eq "100" ) {
            route_del(GW_EMB34);
            route_add(GW_EMB147);
            comment_squid_emb_34();
            log_file( LOG, "$msg{OI_DOWN} - $date" );
            log_file( LOG, "$msg{EMB34_DOWN} - $date" );
            
            # checks if the tertiary link is up before putting the default route
            $packet_loss = get_ping(INT_EMB147);
            if ( $packet_loss eq "100" ) {
                route_add(GW_OI);
                route_del(GW_EMB147);
                restore_squid_oi(SQUID);
                restore_squid_emb_34(SQUID);
                restore_squid_emb_147(SQUID);
                log_file( LOG, "$msg{EMB147_DOWN} - $date");
            }
            else {
                #send_mail("Status of Link","$msg{LINK_DOWN} - $date");
            }
        }
        else {
            log_file( LOG, "$msg{OI_DOWN} - $date" );
            #send_mail("Status of Link","$msg{OI_DOWN} - $date");
        }
    }
    else {
        log_file( LOG, "$msg{OI_UP} - $date" );
        $dbh->do("UPDATE Current SET id_status = 1 WHERE id_link = 2");
        
        my $SQL = $dbh->prepare("SELECT L.name, S.description FROM 
                                Link L, Current C, Status S 
                                WHERE L.id = C.id_link 
                                AND S.id = C.id_status AND S.description = 'ONLINE' AND L.id = 3;");
        $SQL->execute();

        while ( my $row = $SQL->fetchrow_hashref() ) {
            print lc "$row->{name} $row->{description}\n";
        }
        #send_mail("Status of Link","$msg{OI_UP} - $date");
    }
}
elsif ( $gateway eq GW_EMB34 && "$interface" eq INT_EMB34 ) {
    route_add(GW_OI);

    # checks if the main link again
    $packet_loss = get_ping(INT_OI);
    if ( $packet_loss eq "0" ) {
        route_del(GW_EMB34);
        log_file( LOG, "LINK OI VOLTOU - $date" );
        $dbh->do("UPDATE Current SET id_status = 1 WHERE id_link = 3");
        #send_mail("Status of Link","LINK DA OI VOLTOU - $date");
        restore_squid_oi(SQUID);
    }
    else {
        route_del(GW_OI);
        log_file( LOG, "LINK OI CONTINUA DOWN - $date" );

        # check if link secondary is down!
        $packet_loss = get_ping(INT_EMB34);
        if ( $packet_loss eq "100" ) {
            route_add(GW_EMB147);
            route_del(GW_EMB34);
            comment_squid_emb_34();
            log_file( LOG, "$msg{EMB34_DOWN} - $date" );
            ##send_mail("Status of Link","$msg{EMB34_DOWN} - $date");
            $packet_loss = get_ping(INT_EMB147);

           # checks if the tertiary link is down before putting in default route
            if ( $packet_loss eq "100" ) {
                route_del(GW_EMB147);
                log_file( LOG, "NO MOMENTO TODOS OS LINKS ESTÃO DOWN - $date" );
                route_add(GW_OI);
                restore_squid_oi();
                restoure_squid_emb_34();
            }
            else {
               # send_mail("Status of Link","$msg{EMB34_DOWN} - $date");
            }
        }
        else {
             #send_mail("Status of Link","LINK DA OI CONTINUA DOWN - $date");
        }
    }
}
elsif ( $gateway eq GW_EMB147 && $interface eq INT_EMB147 ) {
    route_add(GW_OI);
    $packet_loss = get_ping(INT_OI);
    if ( $packet_loss eq "0" ) {
        route_del(GW_EMB147);
        restore_squid_oi(SQUID);
        log_file( LOG, "LINK OI VOLTOU - $date" );
        $dbh->do("UPDATE Current SET id_status = 1 WHERE id_link = 3");
        #send_mail("Status of Link","LINK DA OI VOLTOU - $date");
    }
    else {
        route_del(GW_OI);
        log_file( LOG, "LINK OI CONTINUA DOWN - $date" );
        $packet_loss = get_ping(INT_EMB147);
        if ( $packet_loss eq "100" ) {
            route_add(GW_OI);
            route_del(GW_EMB147);
            restore_squid_oi(SQUID);
            restore_squid_emb_34(SQUID);
            restore_squid_emb_147(SQUID);
            log_file( LOG, "NO MOMENTO TODOS OS LINKS ESTÃO DOWN - $date" );
        }
        else {
            #send_mail("Status of Link","LINK DA OI CONTINUA DOWN - $date");
        }
    }
}
else {
    log_file( LOG, "NO MOMENTO O SERVIDOR ENCONTRA-SE SEM ROTA DEFAULT - $date" ),
}

my @rule = &ip_rule_list;

# começando os testes para o link da embratel 201.73.62.34
my $rule_add_34   = rule_emb("add", $options{destino}, "LINK3");
my $ping_34       = ping_emb($options{destino});
my $rule_del_34   = rule_emb("del", $options{destino}, "LINK3");

my $emb_34    = check_comment_squid_34(SQUID);

# testa se o ping é igaul a 100%
my @ips_34;
if ( $ping_34 eq "100" ) {
    $dbh->do("UPDATE Current SET id_status = 2 WHERE id_link = 2");
    if ( $emb_34 eq "1" ) { comment_squid_emb_34(SQUID); }
    if ( @rule ) {
        foreach ( @rule ) {
            if ( /LINK3/ ) {
                if ( /((172|192)\.(\d{1,3}\.){2}\d{1,3}\/?\d?\d?)/ ) {
                    unshift(@ips_34, $1);
                }  
            }
        }

        # removendo as regras de firewall  
        if ( @ips_34 ) {
            foreach ( @ips_34 ) {
                my @t = iptables_save($_);
                foreach ( @t ) {
                    if ( /forward/gi ) {
                        ipt_forward("-D", $_);
                    }
                    elsif ( /prerouting/gi ) {
                        ipt_nat("-D", $_);
                    }
                  
                }     
            }
        }

        # removendo as rules
        foreach ( @rule ) {
            if ( /LINK3/ ) {
                rule_del($_);
            }
        }
    }
}
else {
    $dbh->do("UPDATE Current SET id_status = 1 WHERE id_link = 2");
    my $SQL = $dbh->prepare("SELECT L.name, S.description FROM 
                         Link L, Current C, Status S 
                         WHERE L.id = C.id_link 
                         AND S.id = C.id_status AND S.description = 'ONLINE' AND L.id = 2;");
    $SQL->execute();

    while ( my $row = $SQL->fetchrow_hashref() ) {
        print lc "$row->{name} $row->{description}\n";
    }

    my $emb_34 = check_comment_squid_34(SQUID);
    
    if ( $emb_34 eq 0 ) {
        restore_squid_emb_34(SQUID);
    }

    # inicia a flag desligado
    my $has_34 = 0;

    foreach ( @rule ) {
        # se tiver algum LINK3 ele muda a flag
        $has_34 = 1 if /LINK3/;
    }

    # se tiver link34 ele não faz nada senão tiver ele insere o que tiver no @has_link34
    if ( ! $has_34 ) {
        map { rule_add( $_ ) } &r_add_34($options{fwbuilder});

        # ips de regras de fw que ficará no link 201.73.62.34
        my @fw_ips_34;
        map { unshift(@fw_ips_34, $_)  } &r_add_34($options{fwbuilder});
        @fw_ips_34 = map {  /(\d+\.\d+\.\d+\.\d+)/; $1 } grep { /\d+\.\d+\.\d+\.\d+/; } @fw_ips_34;

        my @add_ipt_34;
        foreach my $add ( &add_ipt($options{fwbuilder}) ) {
            foreach my $ip ( @fw_ips_34 ) {
                if ( $add =~ /$ip/ and $add =~ /forward|prerouting/gi ) {
                    $add =~ s/\s+\$IPTABLES //g and $add =~ s/-t nat -A |-A // and $add =~ s/In_RULE_\d{1,3}/ACCEPT/;
                    push(@add_ipt_34, $add);
                }
            }
        }

        # adicionando regras de firewall do link 201.73.62.34
        foreach ( @add_ipt_34 ) {
            if ( /forward/gi ) {
                &ipt_forward("-I", $_);
            }
            elsif ( /prerouting/gi ) {
                &ipt_nat("-I", $_);
            }
        }
    }
} 

# começando os testes para o link da embratel 201.73.254.147
my $rule_add_147   = rule_emb("add", $options{destino}, "LINK2");
my $ping_147       = ping_emb($options{destino});
my $rule_del_147   = rule_emb("del", $options{destino}, "LINK2");

my $emb_147    = check_comment_squid_147(SQUID);

# testa se o ping é igaul a 100%
my @ips_147;
if ( $ping_147 eq "100" ) {
    $dbh->do("UPDATE Current SET id_status = 2 WHERE id_link = 1");
    if ( $emb_147 eq "1" ) { comment_squid_emb_147(SQUID); }
    if ( @rule ) {
        foreach ( @rule ) {
            if ( /LINK2/ ) {
                if ( /((172|192)\.(\d{1,3}\.){2}\d{1,3}\/?\d?\d?)/ ) {
                    unshift(@ips_147, $1);
                }  
            }
        }

        # removendo as regras de firewall  
        if ( @ips_147 ) {
            foreach ( @ips_147 ) {
                my @t = iptables_save($_);
                foreach ( @t ) {
                    if ( /forward/gi ) {
                        ipt_forward("-D", $_);
                    }
                    elsif ( /prerouting/gi ) {
                        ipt_nat("-D", $_);
                    }
                  
                }     
            }
        }

        # removendo as rules
        foreach ( @rule ) {
            if ( /LINK2/ ) {
                rule_del($_);
            }
        }
    }
}
else {
    $dbh->do("UPDATE Current SET id_status = 1 WHERE id_link = 1");
    my $SQL = $dbh->prepare("SELECT L.name, S.description FROM 
                         Link L, Current C, Status S 
                         WHERE L.id = C.id_link 
                         AND S.id = C.id_status AND S.description = 'ONLINE' AND L.id = 1;");

    $SQL->execute();

    while ( my $row = $SQL->fetchrow_hashref() ) {
        print lc "$row->{name} $row->{description}\n";
    }

    my $emb_147    = check_comment_squid_147(SQUID);
    if ( $emb_147 eq 0 ) {
        restore_squid_emb_147(SQUID);
    }

    # inicia a flag desligado
    my $has_147    = 0;

    foreach ( @rule ) {
         # se tiver algum LINK2 ele muda a flag
         $has_147 = 1 if /LINK2/;
    }
    
    # se tiver link2 ele não faz nada senão tiver ele insere o que tiver no @has_link2
    if ( ! $has_147 ) {
        map { rule_add( $_ ) } &r_add_147($options{fwbuilder});
        
        # ips de regras de fw que ficará no link 201.73.254.147
        my @fw_ips_147;
        map { unshift(@fw_ips_147, $_)  } &r_add_147($options{fwbuilder});
        @fw_ips_147 = map {  /(\d+\.\d+\.\d+\.\d+)/; $1 } grep { /\d+\.\d+\.\d+\.\d+/; } @fw_ips_147;
        
        my @add_ipt_147;
        foreach my $add ( &add_ipt($options{fwbuilder}) ) {
            foreach my $ip ( @fw_ips_147 ) {
                if ( $add =~ /$ip/ and $add =~ /forward|prerouting/gi ) { 
                    $add =~ s/\s+\$IPTABLES //g and $add =~ s/-t nat -A |-A // and $add =~ s/In_RULE_\d{1,3}/ACCEPT/;
                    push(@add_ipt_147, $add);
                }
            }
        }

        # adicionando regras de firewall do link 201.73.254.147
        foreach ( @add_ipt_147 ) {
            if ( /forward/gi ) {
                &ipt_forward("-I", $_);
            }
            elsif ( /prerouting/gi ) {
                &ipt_nat("-I", $_);
            }
        }
    }
}

$dbh->disconnect;

# get default route
sub get_default {
    my $gateway;

    open( ROTA, "route -n|" ) or die "Get route Error! \n";
    my @cmd = (<ROTA>);
    close(ROTA);
    foreach my $line (@cmd) {
        my @s = split( /\s+/, $line );

        if ( $s[0] eq '0.0.0.0' ) {
            $gateway = $s[1];
        }
    }
    return $gateway;
}

# get interface link default
sub get_int {
    my $int;

    open( ROTA, "route -n|" ) or die "Get interface Error! \n";
    my @cmd = (<ROTA>);
    close(ROTA);
    foreach my $line (@cmd) {
        my @s = split( /\s+/, $line );

        if ( $s[0] eq '0.0.0.0' ) {
            $int = $s[7];
        }
    }
    return $int;
}

# get packet loss
sub get_ping {
    my $loss;
    my $int = shift;
    open( PING, "ping -I " . $int . " -c3 " . DESTINO . "|" )
      or die "PING Error! \n";
    my @line = (<PING>);
    close(PING);
    foreach my $l (@line) {
        if ( $l =~ m/(\d+)%/ ) {
            $loss = "$1";
        }
    }
    return $loss;
}

# add route default
sub route_add {
    my $ip = shift;
    open( ROTA, "route add default gw $ip |" ) or die "Route add Error! \n";
    close(ROTA);
}

# delete route default
sub route_del {
    my $ip = shift;
    open( ROTA, "route del default gw $ip |" ) or die "Route del Error! \n";
    close(ROTA);
}

sub check_comment_squid_34 {
    my $file = shift;
    open( FILE, "<", $file ) or die "Error! file not found!\n";
    my @lines = <FILE>;
    close(FILE);

    my $i;
    foreach ( @lines ) {
        if ( m/#tcp_outgoing_address/ and m/201.73.62.34/ ) {  $i++; }
        if ( m/#always_direct/ and m/link_10m[^2]/ ) { $i++; }
        if ( m/#always_direct/ and m/liberado_10m[^2]/ ) { $i++; }
    }

    return 0 if defined $i;
    return 1;
}

sub check_comment_squid_147 {
    my $file = shift;
    open( FILE, "<", $file ) or die "Error! file not found!\n";
    my @lines = <FILE>;
    close(FILE);

    my $i;
    foreach ( @lines ) {
        if ( m/#tcp_outgoing_address/ and m/201.73.254.147/ ) { $i++; }
        if ( m/#always_direct/ and m/link_10m2/ ) { $i++; }
        if ( m/#always_direct/ and m/liberado_10m2/ ) { $i++; }
    }

    return 0 if defined $i;
    return 1; 
}


sub check_link_emb {
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

# writing log files
sub log_file {
    my $file = shift;
    my $msg  = shift;
    open( my $fh, ">>", "$file" ) or die "Error Writes log \n";
    return print $fh "$msg \n";
    close($fh);
}

# capture data
sub get_date {
    my $dt = localtime(time);
    return $dt->ymd . "\t " . $dt->hms;
}

# getting the number of the backup
sub number_bkp {

    my $file_read = $_[0];
    my $number;

    my @position_letter_p = split( "-", $file_read );

    for my $idf (@position_letter_p) {
        if ( $idf =~ /bkp/ ) {
            my $length = length($idf);
            $number = substr( $idf, 3, $length );
        }
    }
    $number = 0 if $number eq "";

    return $number;

    exit;
}

# backing up squid
sub bkp_squid {

    # list the directory
    my $bkp_dir     = shift;
    my $last_number = 0;
    opendir( DIR, "$bkp_dir" ) or die "Error Directory!";
    my @list = readdir(DIR);
    closedir(DIR);

    # get the current date
    my $date_today = strftime "%Y-%m-%d", localtime;

    # separates in an array all backup files with the current date and captures the last file (the current date)
    my $number_exists = 0;
    foreach my $file (@list) {
        my $file_l        = qq~$file~;
        my $size_string   = length($file_l);
        my $date_file_get = substr( $file_l, ( $size_string - 10 ), 10 );
        if ( $date_file_get eq $date_today ) {
            $number_exists++;
            my $last_file = number_bkp($file_l);
            if ( $last_number < $last_file ) { $last_number = $last_file; }
        }
    }

    # sets the name of the new file
    my $new_file;
    if ( $number_exists == 0 ) {
        $new_file = "squid.conf-bkp" . "-" . $date_today;
    }
    else {
        my $number_new = $last_number + 1;
        $new_file = "squid.conf-bkp" . $number_new . "-" . $date_today;
    }

    # create the new file of backup
    copy SQUID, "$bkp_dir/$new_file";
    return $new_file;
}

sub comment_squid_oi {

    #Specify the file
    my $file = SQUID;

    bkp_squid(BKP);

    #Open the file and read data
    #Die with grace if it fails
    open( FILE, "<", "$file" ) or die "Can't open $file: $!\n";
    my @lines = <FILE>;
    close(FILE);

    open( SQUID_OI, ">", "$file" ) or die "Can't open $file: $!\n";

    foreach (@lines) {
        if (/^[^#]/){
            s/tcp_outgoing/#tcp_outgoing/ if m/201.18.32.26/;
            s/always_direct/#always_direct/ if m/liberado_2m/;
            s/always_direct/#always_direct/ if m/link_2m/;
        }        
        print SQUID_OI;
    }

    close(SQUID_OI);
}

sub comment_squid_emb_34 {

    #Specify the file
    my $file = SQUID;

    bkp_squid(BKP);

    #Open the file and read data
    #Die with grace if it fails
    open( FILE, "<", "$file" ) or die "Can't open $file: $!\n";
    my @lines = <FILE>;
    close(FILE);

    open( SQUID_EMB_34, ">", "$file" ) or die "Can't open $file: $!\n";

    foreach (@lines) {
        if (/^[^#]/){
            s/tcp_outgoing/#tcp_outgoing/ if m/201.73.62.34/;
            s/always_direct/#always_direct/ if m/liberado_10m[^2]/;
            s/always_direct/#always_direct/ if m/link_10m[^2]/;
        }
        print SQUID_EMB_34;
    }

    close(SQUID_EMB_34);
}

sub comment_squid_emb_147 {

    #Specify the file
    my $file = SQUID;

    bkp_squid(BKP);

    #Open the file and read data
    #Die with grace if it fails
    open( FILE, "<", "$file" ) or die "Can't open $file: $!\n";
    my @lines = <FILE>;
    close(FILE);

    open( SQUID_EMB_147, ">", "$file" ) or die "Can't open $file: $!\n";

    foreach (@lines) {
        if (/^[^#]/){
            s/tcp_outgoing/#tcp_outgoing/ if m/201.73.254.147/;
            s/always_direct/#always_direct/ if m/liberado_10m2/;
            s/always_direct/#always_direct/ if m/link_10m2/;
        }
        print SQUID_EMB_147;
    }

    close(SQUID_EMB_147);
}

sub restore_squid_oi {
    my $file = shift;

    open( FILE, "<", "$file" ) or die "Error file not found! \n";
    my @list = <FILE>;
    close(FILE);

    open( SQUID_OI, ">", "$file" ) or die "Error, file not found! \n";
    
    foreach (@list) {
        if (/^#/) {
            s/#tcp_outgoing_address/tcp_outgoing_address/ if /201.18.32.26/;
            s/#always_direct/always_direct/ if /link_2m/;
            s/#always_direct/always_direct/ if /liberado_2m/;
        }
        print SQUID_OI;
    }
    close(SQUID_OI);
}

sub restore_squid_emb_34 {
    my $file = shift;

    open( FILE, "<", "$file" ) or die "Error file not found! \n";
    my @list = <FILE>;
    close(FILE);

    open( SQUID_EMB_34, ">", "$file" ) or die "Error, file not found! \n";

    foreach (@list) {
        if (/^#/) {
            s/#tcp_outgoing_address/tcp_outgoing_address/ if /201.73.62.34/;
            s/#always_direct/always_direct/ if /link_10m[^2]/;
            s/#always_direct/always_direct/ if /liberado_10m[^2]/;
        }
        print SQUID_EMB_34;
    }
    close(SQUID_EMB_34);
}

sub restore_squid_emb_147 {
     my $file = shift;

     open( FILE, "<", "$file" ) or die "Error file not found! \n";
     my @list = <FILE>;
     close(FILE);

     open( SQUID_EMB_147, ">", "$file" ) or die "Error, file not found! \n";

     foreach (@list) {
         if (/^#/) {
             s/#tcp_outgoing_address/tcp_outgoing_address/ if /201.73.254.147/;
             s/#always_direct/always_direct/ if /link_10m2/;
             s/#always_direct/always_direct/ if /liberado_10m2/;
         }
         print SQUID_EMB_147;
     }
     close(SQUID_EMB_147);
 }

sub send_mail {
    my $subject  = shift;
    my $body     = shift;

    my $smtp = new Net::SMTP::TLS(
        'smtp.gmail.com',
        Port     => 587,
        User     => 'tacitochaves@gmail.com',
        Password => '**********',
        Timeout  => 30,
    );

    # -- Enter email FROM below. --
    $smtp->mail('tacitochaves@gmail.com');

    # -- Enter recipient mails addresses below --
    my @recipients = ( 'tacito.ma@hotmail.com', 'tacitoregis.ma@hotmail.com' );
    $smtp->recipient(@recipients);

    $smtp->data();

    # This part creates the SMTP headers you see
    $smtp->datasend("To: tacito\@hotmail.com\n");
    $smtp->datasend("From: tacito.chaves\@gmail.com\n");
    $smtp->datasend("Content-Type: text/html \n");
    $smtp->datasend("Subject: $subject");

    # line break to separate headers from message body
    $smtp->datasend("\n");
    $smtp->datasend("$body");
    $smtp->datasend("\n");
    $smtp->dataend();

    $smtp->quit;
}
